/*
 * QDigiDocCrypto
 *
 * Copyright (C) 2009-2011 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009-2011 Raul Metsma <raul@innovaatik.ee>
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

#include "Application.h"
#include "Poller.h"

#include <common/Common.h>
#include <common/MessageBox.h>
#include <common/SslCertificate.h>
#include <common/TokenData.h>

#include <libdigidoc/DigiDocCert.h>
#include <libdigidoc/DigiDocConvert.h>
#include <libdigidoc/DigiDocGen.h>
#include <libdigidoc/DigiDocEncGen.h>
#include <libdigidoc/DigiDocEncSAXParser.h>
#include <libdigidoc/DigiDocPKCS11.h>
#include <libdigidoc/DigiDocSAXParser.h>

#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QInputDialog>
#include <QTemporaryFile>

class CryptoDocPrivate
{
public:
	CryptoDocPrivate(): enc(0), doc(0) {}

	void cleanProperties();
	void deleteDDoc();
	void removeFolder( const QString &path );

	QString			ddoc, ddocTemp;
	QString			fileName;
	DEncEncryptedData *enc;
	SignedDoc		*doc;
};



void CKey::setCert( const QSslCertificate &c )
{
	cert = c;
	recipient = SslCertificate(c).friendlyName();
}



void CryptoDocPrivate::cleanProperties()
{
	for( int i = enc->encProperties.nEncryptionProperties - 1; i >= 0; --i )
	{
		DEncEncryptionProperty *p = enc->encProperties.arrEncryptionProperties[i];
		if( qstrncmp( p->szName, "orig_file", 9 ) == 0 )
			dencEncryptedData_DeleteEncryptionProperty( enc, i );
	}
}

void CryptoDocPrivate::deleteDDoc()
{
	SignedDoc_free( doc );
	doc = 0;
	if( ddocTemp.isEmpty() )
		return;

	removeFolder( ddocTemp );
	ddoc.clear();
	ddocTemp.clear();
}

void CryptoDocPrivate::removeFolder( const QString &path )
{
	QDir d( path );
	if( !d.exists() )
		return;
	Q_FOREACH( const QFileInfo &file, d.entryInfoList( QDir::Files|QDir::NoDotAndDotDot ) )
	{
		QFile f( file.filePath() );
		f.setPermissions( QFile::ReadOwner|QFile::WriteOwner );
		f.remove();
	}
	d.rmdir( path );
}



CryptoDoc::CryptoDoc( QObject *parent )
:	QObject( parent )
,	d( new CryptoDocPrivate )
{}

CryptoDoc::~CryptoDoc() { clear(); delete d; }

void CryptoDoc::addFile( const QString &file, const QString &mime )
{
	if( isEncryptedWarning() )
		return;

	DataFile *data = 0;
	int err = DataFile_new( &data, d->doc, NULL, file.toUtf8(),
		CONTENT_EMBEDDED_BASE64, mime.toUtf8(), 0, NULL, 0, NULL, CHARSET_UTF_8 );
	if( err != ERR_OK )
	{
		if( data )
			DataFile_delete( d->doc, data->szId );
		return setLastError( tr("Failed to add file"), err );
	}

	err = calculateDataFileSizeAndDigest( d->doc, data->szId, file.toUtf8(), DIGEST_SHA1 );
	if( err != ERR_OK )
	{
		DataFile_delete( d->doc, data->szId );
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
	err = dencEncryptedKey_new( d->enc, &pkey, cert, DENC_ENC_METHOD_RSA1_5,
		NULL, key.recipient.toUtf8(), NULL, NULL );
	if( err != ERR_OK )
		setLastError( tr("Failed to add key"), err );
	return err == ERR_OK;
}

void CryptoDoc::clear()
{
	dencEncryptedData_free( d->enc );
	d->enc = 0;
	d->deleteDDoc();
	d->fileName.clear();
}

void CryptoDoc::create( const QString &file )
{
	clear();
	const char *format = "DIGIDOC-XML"; //ConfigIted->lookup("DIGIDOC_FORMAT");
	const char *version = "1.3"; //ConfigIted->lookup("DIGIDOC_VERSION");

	int err = SignedDoc_new( &d->doc, format, version );
	if( err != ERR_OK )
		return setLastError( tr("Internal error"), err );

	err = dencEncryptedData_new( &d->enc, DENC_XMLNS_XMLENC, DENC_ENC_METHOD_AES128, 0, 0, 0 );
	if( err != ERR_OK )
	{
		setLastError( tr("Internal error"), err );
		clear();
		return;
	}
	d->fileName = file;
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
	for( int i = 0; i < d->enc->nEncryptedKeys; ++i )
	{
		DEncEncryptedKey *tmp = d->enc->arrEncryptedKeys[i];
		if( qApp->poller()->token().cert() == SslCertificate::fromX509( Qt::HANDLE(tmp->pCert) ) )
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
	bool decrypted = false;
	while( !decrypted )
	{
		switch( qApp->poller()->decrypt( in, out ) )
		{
		case Poller::DecryptOK: decrypted = true; break;
		case Poller::PinIncorrect: break;
		default: return false;
		}
	}

	ddocMemAssignData( &d->enc->mbufTransportKey, out.constData(), out.size() );
	d->enc->nKeyStatus = DENC_KEY_STATUS_INITIALIZED;
	int err = dencEncryptedData_decryptData( d->enc );
	if( err != ERR_OK )
	{
		setLastError( tr("Failed decrypt data"), err );
		return false;
	}

	DEncEncryptionProperty *prop = dencEncryptedData_FindEncryptionPropertyByName( d->enc, ENCPROP_ORIG_SIZE );
	if( prop && prop->szContent )
	{
		long size = QByteArray( prop->szContent ).toLong();
		if( size > 0 && size < d->enc->mbufEncryptedData.nLen )
			d->enc->mbufEncryptedData.nLen = size;
	}

	QString docName = QFileInfo( d->fileName ).fileName();
	d->ddocTemp = Common::tempFilename();
	d->removeFolder( d->ddocTemp );
	QDir().mkdir( d->ddocTemp );

	d->ddoc = QString( "%1/%2.ddoc" ).arg( d->ddocTemp ).arg( docName );
	QFile f( d->ddoc );
	if( !f.open( QIODevice::WriteOnly|QIODevice::Truncate ) )
	{
		setLastError( tr("Failed to create temporary files<br />%1").arg( f.errorString() ) );
		return false;
	}
	f.write( (const char*)d->enc->mbufEncryptedData.pMem, d->enc->mbufEncryptedData.nLen );
	f.close();
	ddocMemBuf_free( &d->enc->mbufEncryptedData );

	err = ddocSaxReadSignedDocFromFile( &d->doc, f.fileName().toUtf8(), 0, 0 );
	if( err != ERR_OK )
	{
		setLastError( tr("Failed to read decrypted data"), err );
		return false;
	}

	for( int i = 0; i < d->doc->nDataFiles; ++i )
	{
		QString file = QString( "%1/%2" ).arg( d->ddocTemp )
			.arg( QString::fromUtf8( d->doc->pDataFiles[i]->szFileName ) );
		if( QFile::exists( file ) )
			QFile::remove( file );
		err = ddocSaxExtractDataFile( d->doc, d->ddoc.toUtf8(),
			file.toUtf8(), d->doc->pDataFiles[i]->szId, CHARSET_UTF_8 );
		if( err == ERR_OK )
		{
			ddocMemAssignString( &d->doc->pDataFiles[i]->szFileName, file.toUtf8() );
			QFile::setPermissions( file, QFile::ReadOwner );
		}
		else
			setLastError( tr("Failed to save file '%1'").arg( file ), err );
	}

	d->cleanProperties();
	return !isEncrypted();
}

QList<CDocument> CryptoDoc::documents()
{
	QList<CDocument> list;
	if( isNull() )
		return list;

	if( isEncrypted() )
	{
		int count = dencOrigContent_count( d->enc );
		for( int i = 0; i < count; ++i )
		{
			char filename[255], size[255], mime[255], id[255];
			dencOrigContent_findByIndex( d->enc, i, filename, size, mime, id );
			CDocument doc;
			doc.filename = QString::fromUtf8( filename );
			doc.mime = QString::fromUtf8( mime );
			doc.size = QString::fromUtf8( size );
			list << doc;
		}
	}
	else if( d->doc )
	{
		for( int i = 0; i < d->doc->nDataFiles; ++i )
		{
			DataFile *data = d->doc->pDataFiles[i];
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
	if( d->enc->nEncryptedKeys < 1 )
	{
		setLastError( tr("No keys specified") );
		return false;
	}

	int err = ERR_OK;

#if 0
	err = dencOrigContent_registerDigiDoc( d->enc, d->doc );
	if( err != ERR_OK )
	{
		setLastError( tr("Failed to encrypt data"), err );
		return false;
	}
#else // To avoid full file path
	err = dencEncryptedData_SetMimeType( d->enc, DENC_ENCDATA_TYPE_DDOC );
	for( int i = 0; i < d->doc->nDataFiles; ++i )
	{
		DataFile *data = d->doc->pDataFiles[i];
		QFileInfo file( QString::fromUtf8( data->szFileName ) );

		if( !file.exists() )
		{
			d->cleanProperties();
			setLastError( tr("Failed to encrypt data.<br />File does not exsist %1").arg( file.filePath() ) );
			return false;
		}

		int err = dencOrigContent_add( d->enc,
			QString("orig_file%1").arg(i).toUtf8(),
			file.fileName().toUtf8(),
			Common::fileSize( data->nSize ).toUtf8(),
			data->szMimeType,
			data->szId );

		if( err != ERR_OK )
		{
			d->cleanProperties();
			setLastError( tr("Failed to encrypt data"), err );
			return false;
		}
	}
#endif

	QFile f( QString( d->fileName ).append( ".ddoc" ) );
	err = createSignedDoc( d->doc, NULL, f.fileName().toUtf8() );
	if( err != ERR_OK )
	{
		d->cleanProperties();
		setLastError( tr("Failed to encrypt data"), err );
		return false;
	}

	if( !f.open( QIODevice::ReadOnly ) )
	{
		d->cleanProperties();
		setLastError( tr("Failed to encrypt data") );
		return false;
	}

	err = dencEncryptedData_AppendData( d->enc, f.readAll(), f.size() );
	if( err != ERR_OK )
	{
		d->cleanProperties();
		setLastError( tr("Failed to encrypt data"), err );
		return false;
	}
	f.close();
	f.remove();

	err = dencEncryptedData_encryptData( d->enc, DENC_COMPRESS_NEVER );
	if( err != ERR_OK )
	{
		d->cleanProperties();
		setLastError( tr("Failed to encrypt data"), err );
		return false;
	}

	d->deleteDDoc();
	return isEncrypted();
}

QString CryptoDoc::fileName() const { return d->fileName; }

bool CryptoDoc::isEncrypted() const
{
	return d->enc &&
		(d->enc->nDataStatus == DENC_DATA_STATUS_ENCRYPTED_AND_COMPRESSED ||
		d->enc->nDataStatus == DENC_DATA_STATUS_ENCRYPTED_AND_NOT_COMPRESSED);
}

bool CryptoDoc::isEncryptedWarning()
{
	if( isNull() )
		setLastError( tr("Container is not open") );
	if( isEncrypted() )
		setLastError( tr("Container is encrypted") );
	return isNull() || isEncrypted();
}

bool CryptoDoc::isNull() const { return d->enc == 0; }
bool CryptoDoc::isSigned() const { return d->doc && d->doc->nSignatures; }

QList<CKey> CryptoDoc::keys()
{
	QList<CKey> list;
	if( isNull() )
		return list;

	for( int i = 0; i < d->enc->nEncryptedKeys; ++i )
	{
		CKey ckey;
		ckey.cert = SslCertificate::fromX509( Qt::HANDLE(d->enc->arrEncryptedKeys[i]->pCert) );
		ckey.id = QString::fromUtf8( d->enc->arrEncryptedKeys[i]->szId );
		ckey.name = QString::fromUtf8( d->enc->arrEncryptedKeys[i]->szKeyName );
		ckey.recipient = QString::fromUtf8( d->enc->arrEncryptedKeys[i]->szRecipient );
		ckey.type = QString::fromUtf8( d->enc->arrEncryptedKeys[i]->szEncryptionMethod );

		list << ckey;
	}

	return list;
}

bool CryptoDoc::open( const QString &file )
{
	clear();
	d->fileName = file;
	int err = dencSaxReadEncryptedData( &d->enc, file.toUtf8() );
	if( err != ERR_OK )
		setLastError( tr("Failed to open crypted document"), err );
	return err == ERR_OK;
}

void CryptoDoc::removeDocument( int id )
{
	if( isEncryptedWarning() )
		return;

	if( !d->doc || id >= d->doc->nDataFiles || !d->doc->pDataFiles[id] )
		return setLastError( tr("Internal error") );

	int err = DataFile_delete( d->doc, d->doc->pDataFiles[id]->szId );
	if( err != ERR_OK )
		setLastError( tr("Failed to remove file"), err );
}

void CryptoDoc::removeKey( int id )
{
	if( isEncryptedWarning() )
		return;

	if( !d->enc || id >= d->enc->nEncryptedKeys || !d->enc->arrEncryptedKeys[id] )
		return setLastError( tr("Internal error") );

	int err = dencEncryptedData_DeleteEncryptedKey( d->enc, id );
	if( err != ERR_OK )
		setLastError( tr("Failed to remove key"), err );
}

void CryptoDoc::save( const QString &filename )
{
	if( isNull() )
		return setLastError( tr("Container is not open") );
	if( !isEncrypted() )
		return setLastError( tr("Container is not crypted") );
	if( !filename.isEmpty() )
		d->fileName = filename;
	int err = dencGenEncryptedData_writeToFile( d->enc, d->fileName.toUtf8() );
	if( err != ERR_OK )
		setLastError( tr("Failed to save encrpyted file"), err );
}

bool CryptoDoc::saveDDoc( const QString &filename )
{
	if( !d->doc )
	{
		setLastError( tr("Document not open") );
		return false;
	}

	// use existing ddoc, createSignedDoc breaks signed doc
	if( !d->ddoc.isEmpty() )
	{
		bool result = QFile::copy( d->ddoc, filename );
		if( !result )
			setLastError( tr("Failed to save file") );
		return result;
	}
	else
	{
		int err = createSignedDoc( d->doc, NULL, filename.toUtf8() );
		if( err != ERR_OK )
			setLastError( tr("Failed to save file"), err );
		return err == ERR_OK;
	}
}

void CryptoDoc::saveDocument( int id, const QString &filepath )
{
	if( isEncryptedWarning() )
		return;

	if( id < 0 || !d->doc || id >= d->doc->nDataFiles || !d->doc->pDataFiles[id] )
		return setLastError( tr("Internal error") );

	QString src = QString::fromUtf8( d->doc->pDataFiles[id]->szFileName );
	if( src == filepath )
		return;
	if( QFile::exists( filepath ) )
		QFile::remove( filepath );
	bool err = QFile::copy( src, filepath );
	if( !err )
		return setLastError( tr("Failed to save file"), err );
}

void CryptoDoc::setLastError( const QString &err, int code )
{
	DMessageBox d( QMessageBox::Warning, tr("DigiDoc3 crypto"), err, QMessageBox::Close, qApp->activeWindow() );
	if( code > 0 )
	{
		d.addButton( QMessageBox::Help );
		d.setDetailedText( tr("libdigidoc code: %1\nmessage: %2").arg( code ).arg( getErrorString( code ) ) );
	}
	if( d.exec() == QMessageBox::Help )
		Common::showHelp( err, code );
}
