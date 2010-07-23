/*
 * QDigiDocCrypto
 *
 * Copyright (C) 2009 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009 Raul Metsma <raul@innovaatik.ee>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "CryptoDoc.h"

#include "common/Common.h"
#include "common/SslCertificate.h"
#include "Poller.h"

#include <libdigidoc/DigiDocCert.h>
#include <libdigidoc/DigiDocConfig.h>
#include <libdigidoc/DigiDocConvert.h>
#include <libdigidoc/DigiDocGen.h>
#include <libdigidoc/DigiDocEncGen.h>
#include <libdigidoc/DigiDocEncSAXParser.h>
#include <libdigidoc/DigiDocPKCS11.h>
#include <libdigidoc/DigiDocSAXParser.h>

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QInputDialog>
#include <QTemporaryFile>

void CKey::setCert( const QSslCertificate &c )
{
	cert = c;
	recipient = SslCertificate(c).subjectInfo( QSslCertificate::CommonName );
}



CryptoDoc::CryptoDoc( QObject *parent )
:	QObject( parent )
,	m_enc(0)
,	m_doc(0)
{
	initDigiDocLib();
	QString ini = QString( "%1/digidoc.ini" ).arg( QCoreApplication::applicationDirPath() );
	if( QFileInfo( ini ).isFile() )
		initConfigStore( ini.toUtf8() );
	else
		initConfigStore( NULL );

	poller = new Poller();
	connect( poller, SIGNAL(dataChanged(QStringList,QString,QSslCertificate)),
		SLOT(dataChanged(QStringList,QString,QSslCertificate)) );
	connect( poller, SIGNAL(error(QString,quint8)), SLOT(setLastPollerError(QString,quint8)) );
	poller->start();
}

CryptoDoc::~CryptoDoc()
{
	delete poller;
	cleanupConfigStore( NULL );
	finalizeDigiDocLib();
}

QString CryptoDoc::activeCard() const { return m_card; }

void CryptoDoc::addFile( const QString &file, const QString &mime )
{
	if( isEncryptedWarning() )
		return;

	DataFile *data = 0;
	int err = DataFile_new( &data, m_doc, NULL, file.toUtf8(),
		CONTENT_EMBEDDED_BASE64, mime.toUtf8(), 0, NULL, 0, NULL, CHARSET_UTF_8 );
	if( err != ERR_OK )
	{
		if( data )
			DataFile_delete( m_doc, data->szId );
		return setLastError( tr("Failed to add file"), err );
	}

	err = calculateDataFileSizeAndDigest( m_doc, data->szId, file.toUtf8(), DIGEST_SHA1 );
	if( err != ERR_OK )
	{
		DataFile_delete( m_doc, data->szId );
		setLastError( tr("Failed to calculate digest"), err );
	}
}

bool CryptoDoc::addKey( const CKey &key )
{
	if( isEncryptedWarning() )
		return false;
	if( keys().contains( key ) )
	{
		setLastError( tr("Key already exists") );
		return false;
	}

	X509 *cert = NULL;
	QByteArray data = key.cert.toDer();
	int err = ddocDecodeX509Data( &cert, (const byte*)data.constData(), data.size() );
	if( err != ERR_OK )
	{
		setLastError( tr("Failed to add key"), err );
		return false;
	}

	DEncEncryptedKey *pkey = NULL;
	err = dencEncryptedKey_new( m_enc, &pkey, cert, DENC_ENC_METHOD_RSA1_5,
		NULL, key.recipient.toUtf8(), NULL, NULL );
	if( err != ERR_OK )
		setLastError( tr("Failed to add key"), err );
	return err == ERR_OK;
}

QSslCertificate CryptoDoc::authCert() const { return m_authCert; }

void CryptoDoc::cleanProperties()
{
	for( int i = m_enc->encProperties.nEncryptionProperties - 1; i >= 0; --i )
	{
		DEncEncryptionProperty *p = m_enc->encProperties.arrEncryptionProperties[i];
		if( qstrncmp( p->szName, "orig_file", 9 ) == 0 )
			dencEncryptedData_DeleteEncryptionProperty( m_enc, i );
	}
}

void CryptoDoc::clear()
{
	dencEncryptedData_free( m_enc );
	m_enc = 0;
	deleteDDoc();
	m_fileName.clear();
}

void CryptoDoc::create( const QString &file )
{
	clear();
	const char *format = "DIGIDOC-XML"; //ConfigItem_lookup("DIGIDOC_FORMAT");
	const char *version = "1.3"; //ConfigItem_lookup("DIGIDOC_VERSION");

	int err = SignedDoc_new( &m_doc, format, version );
	if( err != ERR_OK )
		return setLastError( tr("Internal error"), err );

	err = dencEncryptedData_new( &m_enc, DENC_XMLNS_XMLENC, DENC_ENC_METHOD_AES128, 0, 0, 0 );
	if( err != ERR_OK )
	{
		setLastError( tr("Internal error"), err );
		clear();
		return;
	}
	m_fileName = file;
}

void CryptoDoc::dataChanged( const QStringList &cards, const QString &card,
	const QSslCertificate &auth )
{
	bool changed = false;
	if( m_cards != cards )
	{
		changed = true;
		m_cards = cards;
	}
	if( m_card != card )
	{
		changed = true;
		m_card = card;
	}
	if( m_authCert != auth )
	{
		changed = true;
		m_authCert = auth;
	}
	if( changed )
		Q_EMIT dataChanged();
}

bool CryptoDoc::decrypt()
{
	if( isNull() )
	{
		setLastError( tr("Container is not open") );
		return false;
	}
	if( !isEncrypted() )
		return true;

	DEncEncryptedKey *key = 0;
	for( int i = 0; i < m_enc->nEncryptedKeys; ++i )
	{
		DEncEncryptedKey *tmp = m_enc->arrEncryptedKeys[i];
		if( m_authCert == SslCertificate::fromX509( Qt::HANDLE(tmp->pCert) ) )
		{
			key = tmp;
			break;
		}
	}
	if( !key )
	{
		setLastError( tr("You do not have the key to decrypt this document") );
		return false;
	}

	QByteArray in( (const char*)key->mbufTransportKey.pMem, key->mbufTransportKey.nLen ), out;
	while( !poller->decrypt( in, out ) )
	{
		if( poller->errorCode() != Poller::PinIncorrect )
			return false;
	}

	ddocMemAssignData( &m_enc->mbufTransportKey, out.constData(), out.size() );
	m_enc->nKeyStatus = DENC_KEY_STATUS_INITIALIZED;
	int err = dencEncryptedData_decryptData( m_enc );
	if( err != ERR_OK )
	{
		setLastError( tr("Failed decrypt data"), err );
		return false;
	}

	DEncEncryptionProperty *prop = dencEncryptedData_FindEncryptionPropertyByName( m_enc, ENCPROP_ORIG_SIZE );
	if( prop && prop->szContent )
	{
		long size = QByteArray( prop->szContent ).toLong();
		if( size > 0 && size < m_enc->mbufEncryptedData.nLen )
			m_enc->mbufEncryptedData.nLen = size;
	}

	QString docName = QFileInfo( m_fileName ).fileName();
	m_ddocTemp = QString( "%1/%2" ).arg( QDir::tempPath() ).arg( docName );
	if( QDir().exists( m_ddocTemp ) )
	{
		QDir d( m_ddocTemp );
		Q_FOREACH( const QFileInfo &file, d.entryInfoList( QDir::NoDotAndDotDot|QDir::Files ) )
			QFile::remove( file.absoluteFilePath() );
	}
	else
		QDir().mkdir( m_ddocTemp );

	m_ddoc = QString( "%1/%2.ddoc" ).arg( m_ddocTemp ).arg( docName );
	QFile f( m_ddoc );
	if( !f.open( QIODevice::WriteOnly|QIODevice::Truncate ) )
	{
		setLastError( tr("Failed to create temporary files<br />%1").arg( f.errorString() ) );
		return false;
	}
	f.write( (const char*)m_enc->mbufEncryptedData.pMem, m_enc->mbufEncryptedData.nLen );
	f.close();
	ddocMemBuf_free( &m_enc->mbufEncryptedData );

	err = ddocSaxReadSignedDocFromFile( &m_doc, f.fileName().toUtf8(), 0, 0 );
	if( err != ERR_OK )
	{
		setLastError( tr("Failed to read decrypted data"), err );
		return false;
	}

	for( int i = 0; i < m_doc->nDataFiles; ++i )
	{
		QString file = QString( "%1/%2" ).arg( m_ddocTemp )
			.arg( QString::fromUtf8( m_doc->pDataFiles[i]->szFileName ) );
		if( QFile::exists( file ) )
			QFile::remove( file );
		err = ddocSaxExtractDataFile( m_doc, m_ddoc.toUtf8(),
			file.toUtf8(), m_doc->pDataFiles[i]->szId, CHARSET_UTF_8 );
		if( err == ERR_OK )
		{
			ddocMemAssignString( &m_doc->pDataFiles[i]->szFileName, file.toUtf8() );
			QFile::setPermissions( file, QFile::ReadOwner );
		}
		else
			setLastError( tr("Failed to save file '%1'").arg( file ), err );
	}

	cleanProperties();
	return !isEncrypted();
}

void CryptoDoc::deleteDDoc()
{
	SignedDoc_free( m_doc );
	m_doc = 0;
	if( m_ddocTemp.isEmpty() )
		return;

	QDir d( m_ddocTemp );
	Q_FOREACH( const QFileInfo &file, d.entryInfoList( QDir::Files|QDir::NoDotAndDotDot ) )
	{
		QFile f( file.filePath() );
		f.setPermissions( QFile::ReadOwner|QFile::WriteOwner );
		f.remove();
	}
	d.rmdir( m_ddocTemp );
	m_ddoc.clear();
	m_ddocTemp.clear();
}

QList<CDocument> CryptoDoc::documents()
{
	QList<CDocument> list;
	if( isNull() )
		return list;

	if( isEncrypted() )
	{
		int count = dencOrigContent_count( m_enc );
		for( int i = 0; i < count; ++i )
		{
			char filename[255], size[255], mime[255], id[255];
			dencOrigContent_findByIndex( m_enc, i, filename, size, mime, id );
			CDocument doc;
			doc.filename = QString::fromUtf8( filename );
			doc.mime = QString::fromUtf8( mime );
			doc.size = QString::fromUtf8( size );
			list << doc;
		}
	}
	else if( m_doc )
	{
		for( int i = 0; i < m_doc->nDataFiles; ++i )
		{
			DataFile *data = m_doc->pDataFiles[i];
			CDocument doc;
			doc.path = QString::fromUtf8( data->szFileName );
			doc.filename = QFileInfo( QString::fromUtf8( data->szFileName ) ).fileName();
			doc.mime = QString::fromUtf8( data->szMimeType );
			doc.size = Common::fileSize( data->nSize );
			list << doc;
		}
	}
	return list;
}

bool CryptoDoc::encrypt()
{
	if( isNull() )
	{
		setLastError( tr("Container is not open") );
		return false;
	}
	if( isEncrypted() )
		return true;
	if( m_enc->nEncryptedKeys < 1 )
	{
		setLastError( tr("No keys specified") );
		return false;
	}

	int err = ERR_OK;

#if 0
	err = dencOrigContent_registerDigiDoc( m_enc, m_doc );
	if( err != ERR_OK )
	{
		setLastError( tr("Failed to encrypt data"), err );
		return false;
	}
#else // To avoid full file path
	err = dencEncryptedData_SetMimeType( m_enc, DENC_ENCDATA_TYPE_DDOC );
	for( int i = 0; i < m_doc->nDataFiles; ++i )
	{
		DataFile *data = m_doc->pDataFiles[i];
		QFileInfo file( QString::fromUtf8( data->szFileName ) );

		if( !file.exists() )
		{
			cleanProperties();
			setLastError( tr("Failed to encrypt data.<br />File does not exsist %1").arg( file.filePath() ) );
			return false;
		}

		int err = dencOrigContent_add( m_enc,
			QString("orig_file%1").arg(i).toUtf8(),
			file.fileName().toUtf8(),
			Common::fileSize( data->nSize ).toUtf8(),
			data->szMimeType,
			data->szId );

		if( err != ERR_OK )
		{
			cleanProperties();
			setLastError( tr("Failed to encrypt data"), err );
			return false;
		}
	}
#endif

	QFile f( QString( m_fileName ).append( ".ddoc" ) );
	err = createSignedDoc( m_doc, NULL, f.fileName().toUtf8() );
	if( err != ERR_OK )
	{
		cleanProperties();
		setLastError( tr("Failed to encrypt data"), err );
		return false;
	}

	if( !f.open( QIODevice::ReadOnly ) )
	{
		cleanProperties();
		setLastError( tr("Failed to encrypt data") );
		return false;
	}

	err = dencEncryptedData_AppendData( m_enc, f.readAll(), f.size() );
	if( err != ERR_OK )
	{
		cleanProperties();
		setLastError( tr("Failed to encrypt data"), err );
		return false;
	}
	f.close();
	f.remove();

	err = dencEncryptedData_encryptData( m_enc, DENC_COMPRESS_NEVER );
	if( err != ERR_OK )
	{
		cleanProperties();
		setLastError( tr("Failed to encrypt data"), err );
		return false;
	}

	deleteDDoc();
	return isEncrypted();
}

QString CryptoDoc::fileName() const { return m_fileName; }

bool CryptoDoc::isEncrypted() const
{
	return m_enc &&
		(m_enc->nDataStatus == DENC_DATA_STATUS_ENCRYPTED_AND_COMPRESSED ||
		m_enc->nDataStatus == DENC_DATA_STATUS_ENCRYPTED_AND_NOT_COMPRESSED);
}

bool CryptoDoc::isEncryptedWarning()
{
	if( isNull() )
		setLastError( tr("Container is not open") );
	if( isEncrypted() )
		setLastError( tr("Container is encrypted") );
	return isNull() || isEncrypted();
}

bool CryptoDoc::isNull() const { return m_enc == 0; }
bool CryptoDoc::isSigned() const { return m_doc && m_doc->nSignatures; }

QList<CKey> CryptoDoc::keys()
{
	QList<CKey> list;
	if( isNull() )
		return list;

	for( int i = 0; i < m_enc->nEncryptedKeys; ++i )
	{
		CKey ckey;
		ckey.cert = SslCertificate::fromX509( Qt::HANDLE(m_enc->arrEncryptedKeys[i]->pCert) );
		ckey.id = QString::fromUtf8( m_enc->arrEncryptedKeys[i]->szId );
		ckey.name = QString::fromUtf8( m_enc->arrEncryptedKeys[i]->szKeyName );
		ckey.recipient = QString::fromUtf8( m_enc->arrEncryptedKeys[i]->szRecipient );
		ckey.type = QString::fromUtf8( m_enc->arrEncryptedKeys[i]->szEncryptionMethod );

		list << ckey;
	}

	return list;
}

bool CryptoDoc::open( const QString &file )
{
	clear();
	m_fileName = file;
	int err = dencSaxReadEncryptedData( &m_enc, file.toUtf8() );
	if( err != ERR_OK )
		setLastError( tr("Failed to open crypted document"), err );
	return err == ERR_OK;
}

QStringList CryptoDoc::presentCards() const { return m_cards; }

void CryptoDoc::removeDocument( int id )
{
	if( isEncryptedWarning() )
		return;

	if( !m_doc || id >= m_doc->nDataFiles || !m_doc->pDataFiles[id] )
		return setLastError( tr("Internal error") );

	int err = DataFile_delete( m_doc, m_doc->pDataFiles[id]->szId );
	if( err != ERR_OK )
		setLastError( tr("Failed to remove file"), err );
}

void CryptoDoc::removeKey( int id )
{
	if( isEncryptedWarning() )
		return;

	if( !m_enc || id >= m_enc->nEncryptedKeys || !m_enc->arrEncryptedKeys[id] )
		return setLastError( tr("Internal error") );

	int err = dencEncryptedData_DeleteEncryptedKey( m_enc, id );
	if( err != ERR_OK )
		setLastError( tr("Failed to remove key"), err );
}

void CryptoDoc::save()
{
	if( isNull() )
		return setLastError( tr("Container is not open") );
	if( !isEncrypted() )
		return setLastError( tr("Container is not crypted") );

	int err = dencGenEncryptedData_writeToFile( m_enc, m_fileName.toUtf8() );
	if( err != ERR_OK )
		setLastError( tr("Failed to save encrpyted file"), err );
}

bool CryptoDoc::saveDDoc( const QString &filename )
{
	if( !m_doc )
	{
		setLastError( tr("Document not open") );
		return false;
	}

	int err = createSignedDoc( m_doc, NULL, filename.toUtf8() );
	if( err != ERR_OK )
		setLastError( tr("Failed to save file"), err );
	return err == ERR_OK;
}

void CryptoDoc::saveDocument( int id, const QString &filepath )
{
	if( isEncryptedWarning() )
		return;

	if( !m_doc || id >= m_doc->nDataFiles || !m_doc->pDataFiles[id] )
		return setLastError( tr("Internal error") );

	QString src = QString::fromUtf8( m_doc->pDataFiles[id]->szFileName );
	if( src == filepath )
		return;
	if( QFile::exists( filepath ) )
		QFile::remove( filepath );
	bool err = QFile::copy( src, filepath );
	if( !err )
		return setLastError( tr("Failed to save file"), err );
}

void CryptoDoc::selectCard( const QString &card )
{ QMetaObject::invokeMethod( poller, "selectCard", Qt::QueuedConnection, Q_ARG(QString,card) ); }

void CryptoDoc::setLastError( const QString &err, int code )
{
	QString errMsg;
	if( code > 0 ) errMsg = getErrorString( code );
	Q_EMIT error( err, code, errMsg );
}

void CryptoDoc::setLastPollerError( const QString &err, quint8 code )
{
	switch( code )
	{
	case Poller::PinCanceled: break;
	case Poller::PinIncorrect:
	case Poller::PinLocked:
	default:
		Q_EMIT error( err, -1, QString() );
	}
}
