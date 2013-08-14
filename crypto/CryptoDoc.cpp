/*
 * QDigiDocCrypto
 *
 * Copyright (C) 2009-2013 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009-2013 Raul Metsma <raul@innovaatik.ee>
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

#include "client/Application.h"
#include "Poller.h"

#include <common/FileDialog.h>
#include <common/SslCertificate.h>
#include <common/TokenData.h>

#include <libdigidoc/DigiDocCert.h>
#include <libdigidoc/DigiDocGen.h>
#include <libdigidoc/DigiDocEncGen.h>
#include <libdigidoc/DigiDocEncSAXParser.h>
#include <libdigidoc/DigiDocSAXParser.h>

#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QMimeData>
#include <QtCore/QProcessEnvironment>
#include <QtCore/QTemporaryFile>
#include <QtCore/QThread>
#include <QtCore/QUrl>
#include <QtGui/QDesktopServices>
#if QT_VERSION >= 0x050000
#include <QtWidgets/QMessageBox>
#else
#include <QtGui/QMessageBox>
#endif

class CryptoDocPrivate
{
public:
	CryptoDocPrivate():	ddoc(0), enc(0), doc(0) {}

	void cleanProperties();
	void deleteDDoc();

	CDocumentModel	*documents;
	QTemporaryFile	*ddoc;
	QString			fileName;
	DEncEncryptedData *enc;
	SignedDoc		*doc;
};

class CryptoDocThread: public QThread
{
public:
	CryptoDocThread( bool encrypt, CryptoDocPrivate *_d )
		: m_encrypt(encrypt), d(_d), err(0) {}

	void encrypt();
	void decrypt();
	void run() { m_encrypt ? encrypt() : decrypt(); }
	void waitForFinished()
	{
		QEventLoop e;
		connect( this, SIGNAL(finished()), &e, SLOT(quit()) );
		start();
		e.exec();
	}

	bool m_encrypt;
	CryptoDocPrivate *d;
	int err;
	QString lastError;
};

void CryptoDocThread::encrypt()
{
	int err = dencOrigContent_registerDigiDoc( d->enc, d->doc );
	if( err != ERR_OK )
		return;

	d->ddoc->reset();
	err = dencEncryptedData_AppendData( d->enc, d->ddoc->readAll(), d->ddoc->size() );
	if( err != ERR_OK )
	{
		d->cleanProperties();
		return;
	}

	err = dencEncryptedData_encryptData( d->enc, DENC_COMPRESS_NEVER );
	if( err != ERR_OK )
	{
		d->cleanProperties();
		return;
	}

	d->deleteDDoc();
}

void CryptoDocThread::decrypt()
{
	err = dencEncryptedData_decryptData( d->enc );

	DEncEncryptionProperty *prop = dencEncryptedData_FindEncryptionPropertyByName( d->enc, ENCPROP_ORIG_SIZE );
	if( prop && prop->szContent )
	{
		long size = QByteArray( prop->szContent ).toLong();
		if( size > 0 && size < d->enc->mbufEncryptedData.nLen )
			d->enc->mbufEncryptedData.nLen = size;
	}

	d->ddoc = new QTemporaryFile( QDir().tempPath() + "/XXXXXX" );
	if( !d->ddoc->open() )
	{
		lastError = CryptoDoc::tr("Failed to create temporary files<br />%1").arg( d->ddoc->errorString() );
		return;
	}
	d->ddoc->write( (const char*)d->enc->mbufEncryptedData.pMem, d->enc->mbufEncryptedData.nLen );
	d->ddoc->flush();
	ddocMemBuf_free( &d->enc->mbufEncryptedData );

	err = ddocSaxReadSignedDocFromFile( &d->doc, d->ddoc->fileName().toUtf8(), 0, 0 );
	if( err != ERR_OK )
		lastError = CryptoDoc::tr("Failed to read decrypted data");
	else
		d->cleanProperties();
}



CDocumentModel::CDocumentModel( CryptoDoc *doc )
:	QAbstractTableModel( doc )
,	d( doc )
{
	setSupportedDragActions( Qt::CopyAction );
}

int CDocumentModel::columnCount( const QModelIndex &parent ) const
{ return parent.isValid() ? 0 : NColumns; }

QString CDocumentModel::copy( const QModelIndex &index, const QString &path ) const
{
	if( !d->d->doc || !d->d->ddoc )
		return QString();
	QStringList row = m_data.value( index.row() );
	if( row.value( 1 ).isEmpty() )
		return QString();
	QString dst = QFileInfo( path ).isDir() ? mkpath( index, path ) : path;
	if( QFile::exists( dst ) )
		QFile::remove( dst );

	int err = ddocSaxExtractDataFile( d->d->doc, d->d->ddoc->fileName().toUtf8(),
		dst.toUtf8(), row.value( 1 ).toUtf8(), CHARSET_UTF_8 );
	if( err != ERR_OK )
	{
		d->setLastError( tr("Failed to save file '%1'").arg( dst ), err );
		return QString();
	}
	return dst;
}

QVariant CDocumentModel::data( const QModelIndex &index, int role ) const
{
	QStringList d = m_data.value( index.row() );
	if( d.empty() )
		return QVariant();
	switch( role )
	{
	case Qt::ForegroundRole:
		switch( index.column() )
		{
		case Size: return QColor(Qt::gray);
		default: return QVariant();
		}
	case Qt::DisplayRole:
		switch( index.column() )
		{
		case Name: return d.value( 0 );
		case Mime: return d.value( 2 );
		case Size: return d.value( 3 );
		default: return QVariant();
		}
	case Qt::TextAlignmentRole:
		switch( index.column() )
		{
		case Name:
		case Mime: return int(Qt::AlignLeft|Qt::AlignVCenter);
		case Size: return int(Qt::AlignRight|Qt::AlignVCenter);
		default: return Qt::AlignCenter;
		}
	case Qt::ToolTipRole:
		switch( index.column() )
		{
		case Save: return tr("Save");
		case Remove: return tr("Remove");
		default: return tr("Filename: %1\nFilesize: %2\nMedia type: %3")
			.arg( d.value( 0 ) )
			.arg( d.value( 3 ) )
			.arg( d.value( 2 ) );
		}
	case Qt::DecorationRole:
		switch( index.column() )
		{
		case Save: return QPixmap(":/images/ico_save.png");
		case Remove: return QPixmap(":/images/ico_delete.png");
		default: return QVariant();
		}
	case Qt::SizeHintRole:
		switch( index.column() )
		{
		case Save:
		case Remove: return QSize( 20, 20 );
		default: return QVariant();
		}
	case Qt::UserRole: return d.value( 1 );
	default: return QVariant();
	}
}

Qt::ItemFlags CDocumentModel::flags( const QModelIndex & ) const
{
	return !d->isEncrypted() ? Qt::ItemIsEnabled|Qt::ItemIsSelectable|Qt::ItemIsDragEnabled : Qt::NoItemFlags;
}

QMimeData* CDocumentModel::mimeData( const QModelIndexList &indexes ) const
{
	QList<QUrl> list;
	Q_FOREACH( const QModelIndex &index, indexes )
	{
		if( index.column() != Name )
			continue;
		QString path = copy( index, QDir::tempPath() );
		if( !path.isEmpty() )
			list << QUrl::fromLocalFile( QFileInfo( path ).absoluteFilePath() );
	}
	QMimeData *data = new QMimeData();
	data->setUrls( list );
	return data;
}

QStringList CDocumentModel::mimeTypes() const
{ return QStringList() << "text/uri-list"; }

QString CDocumentModel::mkpath( const QModelIndex &index, const QString &path ) const
{
	QString filename = m_data.value( index.row() ).value( 0 );
#if defined(Q_OS_WIN)
	filename.replace( QRegExp( "[\\\\/*:?\"<>|]" ), "_" );
#else
	filename.replace( QRegExp( "[\\\\]"), "_" );
#endif
	return path.isEmpty() ? filename : path + "/" + filename;
}

void CDocumentModel::open( const QModelIndex &index )
{
	QFileInfo f( copy( index, QDir::tempPath() ) );
	if( !f.exists() )
		return;
#if defined(Q_OS_WIN)
	QStringList exts = QProcessEnvironment::systemEnvironment().value( "PATHEXT" ).split(';');
	exts << ".PIF" << ".SCR";
	if( exts.contains( "." + f.suffix(), Qt::CaseInsensitive ) &&
		QMessageBox::warning( qApp->activeWindow(), tr("DigiDoc3 crypto"),
			tr("This is an executable file! "
				"Executable files may contain viruses or other malicious code that could harm your computer. "
				"Are you sure you want to launch this file?"),
			QMessageBox::Yes|QMessageBox::No, QMessageBox::No ) == QMessageBox::No )
		return;
#endif
	QDesktopServices::openUrl( QUrl::fromLocalFile( f.absoluteFilePath() ) );
}

bool CDocumentModel::removeRows( int row, int count, const QModelIndex &parent )
{
	if( parent.isValid() || d->isEncryptedWarning() )
		return false;

	if( !d->d->doc || row >= d->d->doc->nDataFiles || !d->d->doc->pDataFiles[row] )
	{
		d->setLastError( tr("Internal error") );
		return false;
	}

	beginRemoveRows( parent, row, row + count );
	for( int i = row + count - 1; i >= row; --i )
	{
		int err = DataFile_delete( d->d->doc, d->d->doc->pDataFiles[i]->szId );
		if( err != ERR_OK )
			d->setLastError( tr("Failed to remove file"), err );
		m_data.removeAt( i );
	}
	endRemoveRows();
	return true;
}

void CDocumentModel::revert()
{
	beginResetModel();
	m_data.clear();
	if( d->isNull() )
		return endResetModel();

	if( d->isEncrypted() )
	{
		int count = dencOrigContent_count( d->d->enc );
		for( int i = 0; i < count; ++i )
		{
			char filename[255], size[255], mime[255], id[255];
			dencOrigContent_findByIndex( d->d->enc, i, filename, 255, size, 255, mime, 255, id, 255 );
			m_data << (QStringList()
				<< QString::fromUtf8( filename ).normalized( QString::NormalizationForm_C )
				<< QString()
				<< QString::fromUtf8( mime ).normalized( QString::NormalizationForm_C )
				<< FileDialog::fileSize( QString::fromUtf8( size ).toULong() ).normalized( QString::NormalizationForm_C ));
		}
	}
	else if( d->d->doc )
	{
		for( int i = 0; i < d->d->doc->nDataFiles; ++i )
		{
			DataFile *data = d->d->doc->pDataFiles[i];
			m_data << (QStringList()
				<< QFileInfo( QString::fromUtf8( data->szFileName ).normalized( QString::NormalizationForm_C ) ).fileName()
				<< QString::fromUtf8( data->szId )
				<< QString::fromUtf8( data->szMimeType ).normalized( QString::NormalizationForm_C )
				<< FileDialog::fileSize( data->nSize ).normalized( QString::NormalizationForm_C ));
		}
	}
	endResetModel();
}

int CDocumentModel::rowCount( const QModelIndex &parent ) const
{ return parent.isValid() ? 0 : m_data.size(); }



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
	delete ddoc;
	ddoc = 0;
}



CryptoDoc::CryptoDoc( QObject *parent )
:	QObject( parent )
,	d( new CryptoDocPrivate )
{
	d->documents = new CDocumentModel( this );
}

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

	err = createSignedDoc( d->doc, d->ddoc->fileName().toUtf8(), d->ddoc->fileName().toUtf8() );
	if( err != ERR_OK )
	{
		DataFile_delete( d->doc, data->szId );
		setLastError( tr("Failed to calculate digest"), err );
	}

	d->documents->revert();
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
	const char *format = "DIGIDOC-XML"; //ConfigItem_lookup("DIGIDOC_FORMAT");
	const char *version = "1.3"; //ConfigItem_lookup("DIGIDOC_VERSION");

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

	d->ddoc = new QTemporaryFile( QDir().tempPath() + "/XXXXXX" ),
	d->ddoc->open();
	err = createSignedDoc( d->doc, 0, d->ddoc->fileName().toUtf8() );
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

	CryptoDocThread dec( false, d );
	dec.waitForFinished();
	if( dec.err != ERR_OK )
		setLastError( dec.lastError.isEmpty() ? tr("Failed to decrypt data") : dec.lastError, dec.err );
	else if( !dec.lastError.isEmpty() )
		setLastError( dec.lastError );
	d->documents->revert();
	return !isEncrypted();
}

CDocumentModel* CryptoDoc::documents() const { return d->documents; }

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

	CryptoDocThread dec( true, d );
	dec.waitForFinished();
	if( dec.err != ERR_OK )
		setLastError( dec.lastError.isEmpty() ? tr("Failed to encrypt data") : dec.lastError, dec.err );
	else if( !dec.lastError.isEmpty() )
		setLastError( dec.lastError );
	d->documents->revert();
	return isEncrypted();
}

QString CryptoDoc::fileName() const { return d->fileName; }

bool CryptoDoc::isEncrypted() const
{
	return !d->doc;
/*	return d->enc &&
		(d->enc->nDataStatus == DENC_DATA_STATUS_ENCRYPTED_AND_COMPRESSED ||
		d->enc->nDataStatus == DENC_DATA_STATUS_ENCRYPTED_AND_NOT_COMPRESSED);*/
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
	{
		setLastError( tr("Failed to open crypted document"), err );
		d->fileName.clear();
	}
	d->documents->revert();
	qApp->addRecent( file );
	return err == ERR_OK;
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
	qApp->addRecent( filename );
}

bool CryptoDoc::saveDDoc( const QString &filename )
{
	if( !d->doc )
	{
		setLastError( tr("Document not open") );
		return false;
	}

	// use existing ddoc, createSignedDoc breaks signed doc
	if( d->ddoc )
	{
		bool result = d->ddoc->copy( filename );
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

void CryptoDoc::setLastError( const QString &err, int code )
{
	QMessageBox d( QMessageBox::Warning, tr("DigiDoc3 crypto"), err, QMessageBox::Close, qApp->activeWindow() );
	if( code > 0 )
	{
		d.addButton( QMessageBox::Help );
		d.setDetailedText( tr("libdigidoc code: %1\nmessage: %2").arg( code ).arg( getErrorString( code ) ) );
	}
	if( d.exec() == QMessageBox::Help )
		Common::showHelp( err, code );
}
