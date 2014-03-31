/*
 * QDigiDocCrypto
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
#include "client/QSigner.h"

#include <common/FileDialog.h>
#include <common/SslCertificate.h>
#include <common/TokenData.h>

#include <libdigidoc/DigiDocCert.h>
#include <libdigidoc/DigiDocEncGen.h>
#include <libdigidoc/DigiDocEncSAXParser.h>

#include <QtCore/QBuffer>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QMimeData>
#include <QtCore/QProcessEnvironment>
#include <QtCore/QTemporaryFile>
#include <QtCore/QThread>
#include <QtCore/QUrl>
#include <QtCore/QXmlStreamReader>
#include <QtCore/QXmlStreamWriter>
#include <QtGui/QDesktopServices>
#include <QtNetwork/QSslKey>
#if QT_VERSION >= 0x050000
#include <QtWidgets/QMessageBox>
#else
#include <QtGui/QMessageBox>
#endif

#include <openssl/aes.h>
#include <openssl/rand.h>

class CryptoDocPrivate: public QThread
{
	Q_OBJECT
public:
	enum Operation {
		Decrypt = 0,
		Encrypt = 1
	};
	struct File
	{
		QString name, id, mime, size;
		QByteArray data;
	};

	CryptoDocPrivate(): hasSignature(false), documents(0), ddoc(0), enc(0), encrypted(false), err(0) {}

	inline void writeBase64(QXmlStreamWriter &x, const QByteArray &data)
	{
		for(int i = 0; i < data.size(); i+=48)
			x.writeCharacters(data.mid(i, 48).toBase64() + "\n");
	}
	inline void writeBase64(QXmlStreamWriter &x, QIODevice *data)
	{
		for(int i = 0; i < data->size(); i+=48)
			x.writeCharacters(data->read(48).toBase64() + "\n");
	}
	void run();
	inline void waitForFinished()
	{
		QEventLoop e;
		connect( this, SIGNAL(finished()), &e, SLOT(quit()) );
		start();
		e.exec();
	}
	QByteArray crypto(const QByteArray &iv, const QByteArray &key, const QByteArray &data, Operation op) const;
	void writeCDoc(QIODevice *cdoc, const QByteArray &key, const QByteArray &data, const QString &mime);
	void readDDoc(QIODevice *ddoc);
	void writeDDoc(QIODevice *ddoc);

	QList<File> files;
	QList<CKey> keys;
	bool hasSignature;
	CDocumentModel	*documents;
	QTemporaryFile	*ddoc;
	QString			fileName;
	DEncEncryptedData *enc;
	bool encrypted;
	int err;
	QString lastError;
};

QByteArray CryptoDocPrivate::crypto(const QByteArray &iv, const QByteArray &key, const QByteArray &data, Operation op) const
{
	int size = 0, size2 = 0;
	EVP_CIPHER_CTX ctx;
	int err = EVP_CipherInit(&ctx, EVP_aes_128_cbc(), (unsigned char*)key.constData(), (unsigned char*)iv.constData(), op);
	QByteArray result(data.size() + EVP_CIPHER_CTX_block_size(&ctx), 0);
	err = EVP_CipherUpdate(&ctx, (unsigned char*)result.data(), &size, (const unsigned char*)data.constData(), data.size());
	err = EVP_CipherFinal(&ctx, (unsigned char*)(result.data() + size), &size2);
	result.resize(size + size2);
	return result;
}

void CryptoDocPrivate::run()
{
	if( !encrypted )
	{
		QByteArray data;
		QBuffer buf(&data);
		buf.open(QBuffer::WriteOnly);
		writeDDoc(&buf);
		buf.close();
#ifdef WIN32
		RAND_screen();
#else
		RAND_load_file("/dev/urandom", 1024);
#endif
		unsigned char salt[PKCS5_SALT_LEN], indata[128];
		RAND_bytes(salt, sizeof(salt));
		RAND_bytes(indata, sizeof(indata));

		QByteArray iv(EVP_MAX_IV_LENGTH, 0), key(16, 0);
		int size = EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt, indata, sizeof(indata), 1, (unsigned char*)key.data(), (unsigned char*)iv.data());
		QByteArray result = crypto(iv, key, data, Encrypt);

		QFile cdoc(fileName);
		cdoc.open(QFile::WriteOnly);
		writeCDoc(&cdoc, key, iv + result, DENC_ENCDATA_TYPE_DDOC);
		cdoc.close();

		delete ddoc;
		ddoc = nullptr;
	}
	else
	{
		err = dencEncryptedData_decryptData( enc );

		DEncEncryptionProperty *prop = dencEncryptedData_FindEncryptionPropertyByName( enc, ENCPROP_ORIG_SIZE );
		if( prop && prop->szContent )
		{
			long size = QByteArray( prop->szContent ).toLong();
			if( size > 0 && size < enc->mbufEncryptedData.nLen )
				enc->mbufEncryptedData.nLen = size;
		}

		ddoc = new QTemporaryFile( QDir().tempPath() + "/XXXXXX" );
		if( !ddoc->open() )
		{
			lastError = CryptoDoc::tr("Failed to create temporary files<br />%1").arg( ddoc->errorString() );
			return;
		}
		ddoc->write( (const char*)enc->mbufEncryptedData.pMem, enc->mbufEncryptedData.nLen );
		ddoc->flush();
		ddoc->reset();
		ddocMemBuf_free( &enc->mbufEncryptedData );

		readDDoc(ddoc);
	}
	encrypted = !encrypted;
}

void CryptoDocPrivate::writeCDoc(QIODevice *cdoc, const QByteArray &key, const QByteArray &data, const QString &mime)
{
	QHash<QString,QString> props;
	props["DocumentFormat"] = "ENCDOC-XML|1.1";
	props["LibraryVersion"] = qApp->applicationName() + "|" + qApp->applicationVersion();
	props["Filename"] = QFileInfo(fileName).fileName();

	QString DS = "http://www.w3.org/2000/09/xmldsig#";
	QString DENC = "http://www.w3.org/2001/04/xmlenc#";

	QXmlStreamWriter w(cdoc);
	w.setAutoFormatting(true);
	w.writeStartDocument();
	w.writeNamespace(DENC, "denc");
	w.writeStartElement(DENC, "EncryptedData");
	if(!mime.isEmpty())
		w.writeAttribute("MimeType", mime);

	w.writeStartElement(DENC, "EncryptionMethod");
	w.writeAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#aes128-cbc");
	w.writeEndElement(); //EncryptionMethod

	w.writeNamespace(DS, "ds");
	w.writeStartElement(DS, "KeyInfo");
	for(const CKey &k: keys)
	{
		w.writeStartElement(DENC, "EncryptedKey");
		if(!k.id.isEmpty())
			w.writeAttribute("Id", k.id);
		if(!k.recipient.isEmpty())
			w.writeAttribute("Recipient", k.recipient);

		w.writeStartElement(DENC, "EncryptionMethod");
		w.writeAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#rsa-1_5");
		w.writeEndElement(); //EncryptionMethod

		w.writeStartElement(DS, "KeyInfo");
		w.writeStartElement(DS, "X509Data");
		w.writeStartElement(DS, "X509Certificate");
		writeBase64(w, k.cert.toDer());
		w.writeEndElement(); //X509Certificate
		w.writeEndElement(); //X509Data
		w.writeEndElement(); //KeyInfo
		w.writeStartElement(DENC, "CipherData");

		RSA *rsa = (RSA*)k.cert.publicKey().handle();
		QByteArray chipper(RSA_size(rsa), 0);
		int size = RSA_public_encrypt(key.size(), (unsigned char*)key.constData(), (unsigned char*)chipper.data(), rsa, RSA_PKCS1_PADDING);
		w.writeStartElement(DENC, "CipherValue");
		writeBase64(w, chipper);
		w.writeEndElement(); //CipherValue
		w.writeEndElement(); //CipherData
		w.writeEndElement(); //EncryptedKey
	}
	w.writeEndElement(); //KeyInfo

	w.writeStartElement(DENC, "CipherData");
	w.writeStartElement(DENC, "CipherValue");
	writeBase64(w, data);
	w.writeEndElement(); //CipherValue
	w.writeEndElement(); //CipherData

	w.writeStartElement(DENC, "EncryptionProperties");
	for(QHash<QString,QString>::const_iterator i = props.constBegin(); i != props.constEnd(); ++i)
	{
		w.writeStartElement(DENC, "EncryptionProperty");
		w.writeAttribute("Name", i.key());
		w.writeCharacters(i.value());
		w.writeEndElement(); //EncryptionProperty
	}
	for(const File &file: files)
	{
		w.writeStartElement(DENC, "EncryptionProperty");
		w.writeAttribute("Name", "orig_file");
		w.writeCharacters(QString("%1|%2|%3|%4").arg(file.name).arg(file.data.size()).arg(file.mime).arg(file.id));
		w.writeEndElement(); //EncryptionProperty
	}
	w.writeEndElement(); //EncryptionProperties
	w.writeEndElement(); //EncryptedData
	w.writeEndDocument();
}

void CryptoDocPrivate::readDDoc(QIODevice *ddoc)
{
	files.clear();
	QXmlStreamReader x(ddoc);
	while(!x.atEnd())
	{
		if(!x.readNextStartElement())
			continue;
		if(x.name() == "DataFile")
		{
			File file;
			file.name = x.attributes().value("Filename").toString().normalized(QString::NormalizationForm_C);
			file.id = x.attributes().value("Id").toString().normalized(QString::NormalizationForm_C);
			file.mime = x.attributes().value("MimeType").toString().normalized(QString::NormalizationForm_C);
			x.readNext();
			file.data = QByteArray::fromBase64( x.text().toUtf8() );
			file.size = FileDialog::fileSize(file.data.size());
			files << file;
		}
		else if(x.name() == "Signature")
		{
			hasSignature = true;
			break;
		}
	}
}

void CryptoDocPrivate::writeDDoc(QIODevice *ddoc)
{
	QXmlStreamWriter x(ddoc);
	x.setAutoFormatting(true);
	x.writeStartDocument();
	x.writeDefaultNamespace("http://www.sk.ee/DigiDoc/v1.3.0#");
	x.writeStartElement("SignedDoc");
	x.writeAttribute("format", "DIGIDOC-XML");
	x.writeAttribute("version", "1.3");

	for(int i = 0; i < documents->rowCount(); ++i)
	{
		QModelIndex index = documents->index(i, 0);
		QString name = documents->copy(index, QDir::tempPath());
		QFile f(name);
		if(!f.open(QFile::ReadOnly))
			continue;
		x.writeStartElement("DataFile");
		x.writeAttribute("ContentType", "EMBEDDED_BASE64");
		x.writeAttribute("Filename", QFileInfo(f.fileName()).fileName());
		x.writeAttribute("Id", index.data(Qt::UserRole).toString());
		x.writeAttribute("MimeType", "application/octet-stream");
		x.writeAttribute("Size", QString::number(f.size()));
		x.writeDefaultNamespace("http://www.sk.ee/DigiDoc/v1.3.0#");
		writeBase64(x, &f);
		x.writeEndElement(); //DataFile
		f.close();
		f.remove();
	}

	x.writeEndElement(); //SignedDoc
	x.writeEndDocument();
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
	if( d->d->files.isEmpty() )
		return QString();
	QStringList row = m_data.value( index.row() );
	if( row.value( 1 ).isEmpty() )
		return QString();
	QString dst = QFileInfo( path ).isDir() ? mkpath( index, path ) : path;
	if( QFile::exists( dst ) )
		QFile::remove( dst );

	QFile f(dst);
	if(!f.open(QFile::WriteOnly) || !f.write(d->d->files.value(index.row()).data))
	{
		d->setLastError( tr("Failed to save file '%1'").arg( dst ) );
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

	if( d->d->files.isEmpty() || row >= d->d->files.size() )
	{
		d->setLastError( tr("Internal error") );
		return false;
	}

	beginRemoveRows( parent, row, row + count );
	for( int i = row + count - 1; i >= row; --i )
	{
		d->d->files.removeAt( i );
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
	else if( !d->d->files.isEmpty() )
	{
		for( const CryptoDocPrivate::File &file: d->d->files )
			m_data << (QStringList() << file.name << file.id << file.mime << file.size);
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

	QFile data(file);
	data.open(QFile::ReadOnly);
	CryptoDocPrivate::File f;
	f.id = QString("D%1").arg(d->files.size());
	f.mime = mime;
	f.name = QFileInfo(file).fileName();
	f.data = data.readAll();
	f.size = FileDialog::fileSize(f.data.size());
	d->files << f;

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
	d->keys << key;
	return true;
}

void CryptoDoc::clear( const QString &file )
{
	if( d->enc )
		dencEncryptedData_free( d->enc );
	d->enc = nullptr;
	delete d->ddoc;
	d->ddoc = nullptr;
	d->hasSignature = false;
	d->encrypted = false;
	d->fileName = file;
	d->files.clear();
	d->keys.clear();
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
		if( qApp->signer()->tokenauth().cert() == SslCertificate::fromX509( Qt::HANDLE(tmp->pCert) ) )
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
		switch( qApp->signer()->decrypt( in, out ) )
		{
		case QSigner::DecryptOK: decrypted = true; break;
		case QSigner::PinIncorrect: break;
		default: return false;
		}
	}

	ddocMemAssignData( &d->enc->mbufTransportKey, out.constData(), out.size() );
	d->enc->nKeyStatus = DENC_KEY_STATUS_INITIALIZED;
	d->waitForFinished();
	if( d->err != ERR_OK )
		setLastError( d->lastError.isEmpty() ? tr("Failed to decrypt data") : d->lastError, d->err );
	else if( !d->lastError.isEmpty() )
		setLastError( d->lastError );
	d->documents->revert();
	return !isEncrypted();
}

CDocumentModel* CryptoDoc::documents() const { return d->documents; }

bool CryptoDoc::encrypt( const QString &filename )
{
	if( isNull() )
	{
		setLastError( tr("Container is not open") );
		return false;
	}
	if( isEncrypted() )
		return true;
	if( d->keys.isEmpty() )
	{
		setLastError( tr("No keys specified") );
		return false;
	}
	if( !filename.isEmpty() )
		d->fileName = filename;
	qApp->addRecent( d->fileName );

	d->waitForFinished();
	if( d->err != ERR_OK )
		setLastError( d->lastError.isEmpty() ? tr("Failed to encrypt data") : d->lastError, d->err );
	else if( !d->lastError.isEmpty() )
		setLastError( d->lastError );
	open(d->fileName);
	return isEncrypted();
}

QString CryptoDoc::fileName() const { return d->fileName; }

bool CryptoDoc::isEncrypted() const
{
	return d->encrypted;
}

bool CryptoDoc::isEncryptedWarning()
{
	if( isNull() )
		setLastError( tr("Container is not open") );
	if( isEncrypted() )
		setLastError( tr("Container is encrypted") );
	return isNull() || isEncrypted();
}

bool CryptoDoc::isNull() const { return d->fileName.isEmpty(); }
bool CryptoDoc::isSigned() const { return d->hasSignature; }

QList<CKey> CryptoDoc::keys()
{
	return d->keys;
}

bool CryptoDoc::open( const QString &file )
{
	clear(file);
	int err = dencSaxReadEncryptedData( &d->enc, file.toUtf8() );
	if( err != ERR_OK )
	{
		setLastError( tr("Failed to open encrypted document"), err );
		d->fileName.clear();
	}
	for( int i = 0; i < d->enc->nEncryptedKeys; ++i )
	{
		CKey ckey;
		ckey.cert = SslCertificate::fromX509( Qt::HANDLE(d->enc->arrEncryptedKeys[i]->pCert) );
		ckey.id = QString::fromUtf8( d->enc->arrEncryptedKeys[i]->szId );
		ckey.name = QString::fromUtf8( d->enc->arrEncryptedKeys[i]->szKeyName );
		ckey.recipient = QString::fromUtf8( d->enc->arrEncryptedKeys[i]->szRecipient );
		ckey.type = QString::fromUtf8( d->enc->arrEncryptedKeys[i]->szEncryptionMethod );

		d->keys << ckey;
	}

	d->encrypted = true;
	d->documents->revert();
	qApp->addRecent( file );
	return err == ERR_OK;
}

void CryptoDoc::removeKey( int id )
{
	if( !isEncryptedWarning() )
		d->keys.removeAt(id);
}

bool CryptoDoc::saveDDoc( const QString &filename )
{
	if( !d->ddoc )
	{
		setLastError( tr("Document not open") );
		return false;
	}

	bool result = d->ddoc->copy( filename );
	if( !result )
		setLastError( tr("Failed to save file") );
	return result;
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

#include "CryptoDoc.moc"
