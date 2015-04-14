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
#include "client/FileDialog.h"
#include "client/QSigner.h"

#include <common/Settings.h>
#include <common/SslCertificate.h>
#include <common/TokenData.h>

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

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#define MIME_XML  "text/xml"
#define MIME_ZLIB "http://www.isi.edu/in-noes/iana/assignments/media-types/application/zip"
#define MIME_DDOC "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd"
#define MIME_DDOC_OLD "http://www.sk.ee/DigiDoc/1.3.0/digidoc.xsd"

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

	CryptoDocPrivate(): hasSignature(false), encrypted(false), documents(nullptr), ddoc(nullptr) {}

	QByteArray crypto(const QByteArray &iv, const QByteArray &key, const QByteArray &data, Operation op) const;
	bool isEncryptedWarning();
	QByteArray readCDoc(QIODevice *cdoc, bool data);
	void readDDoc(QIODevice *ddoc);
	void run();
	void setLastError(const QString &err);
	QString size(const QString &size)
	{
		bool converted = false;
		quint64 result = size.toUInt(&converted);
		return converted ? FileDialog::fileSize(result) : size;
	}
	inline void waitForFinished()
	{
		QEventLoop e;
		connect( this, SIGNAL(finished()), &e, SLOT(quit()) );
		start();
		e.exec();
	}
	inline void writeBase64(QXmlStreamWriter &x, const QString &ns, const QString &name, const QByteArray &data)
	{
		x.writeStartElement(ns, name);
		for(int i = 0; i < data.size(); i+=48)
			x.writeCharacters(data.mid(i, 48).toBase64() + "\n");
		x.writeEndElement();
	}
	void writeCDoc(QIODevice *cdoc, const QByteArray &key, const QByteArray &data, const QString &file, const QString &ver, const QString &mime);
	void writeDDoc(QIODevice *ddoc);

	QString			method, mime, fileName, lastError;
	QByteArray		key;
	QHash<QString,QString> properties;
	QList<CKey>		keys;
	QList<File>		files;
	bool			hasSignature, encrypted;
	CDocumentModel	*documents;
	QTemporaryFile	*ddoc;
};

QByteArray CryptoDocPrivate::crypto(const QByteArray &iv, const QByteArray &key, const QByteArray &data, Operation op) const
{
	int size = 0, size2 = 0;
	EVP_CIPHER_CTX ctx;
	int err = EVP_CipherInit(&ctx, EVP_aes_128_cbc(), (unsigned char*)key.constData(), (unsigned char*)iv.constData(), op);
	QByteArray result(data.size() + EVP_CIPHER_CTX_block_size(&ctx), 0);
	err = EVP_CipherUpdate(&ctx, (unsigned char*)result.data(), &size, (const unsigned char*)data.constData(), data.size());
	err = EVP_CipherFinal(&ctx, (unsigned char*)result.data() + size, &size2);
	result.resize(size + size2);
	return result;
}

bool CryptoDocPrivate::isEncryptedWarning()
{
	if( fileName.isEmpty() )
		setLastError( CryptoDoc::tr("Container is not open") );
	if( encrypted )
		setLastError( CryptoDoc::tr("Container is encrypted") );
	return fileName.isEmpty() || encrypted;
}

void CryptoDocPrivate::run()
{
	if( !encrypted )
	{
		QBuffer data;
		data.open(QBuffer::WriteOnly);

		QString mime, name;
		if(files.size() > 1 || Settings(qApp->applicationName()).value("cdocwithddoc", false).toBool())
		{
			writeDDoc(&data);
			mime = MIME_DDOC;
			name = QFileInfo(fileName).completeBaseName() + ".ddoc";
		}
		else
		{
			data.write(files[0].data);
			mime = files[0].mime;
			name = files[0].name;
		}

		// add ANSIX923 padding
		QByteArray ansix923(16 - (data.size() % 16), 0);
		ansix923[ansix923.size() - 1] = ansix923.size();
		data.write(ansix923);
		data.close();

#ifdef WIN32
		RAND_screen();
#else
		RAND_load_file("/dev/urandom", 1024);
#endif
		unsigned char salt[PKCS5_SALT_LEN], indata[128];
		RAND_bytes(salt, sizeof(salt));
		RAND_bytes(indata, sizeof(indata));

		QByteArray iv(EVP_MAX_IV_LENGTH, 0), key(16, 0);
		EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt, indata, sizeof(indata),
			1, (unsigned char*)key.data(), (unsigned char*)iv.data());
		QByteArray result = crypto(iv, key, data.data(), Encrypt);
		result.prepend(iv);

		QFile cdoc(fileName);
		cdoc.open(QFile::WriteOnly);
		writeCDoc(&cdoc, key, result, name, "1.0", mime);
		cdoc.close();

		delete ddoc;
		ddoc = nullptr;
	}
	else
	{
		QFile cdoc(fileName);
		cdoc.open(QFile::ReadOnly);
		QByteArray result = readCDoc(&cdoc, true);
		cdoc.close();

		result = crypto(result.left(16), key, result.mid(16), Decrypt);

		// remove ANSIX923 padding
		if(result.size() > 0)
		{
			QByteArray ansix923(result[result.size()-1], 0);
			ansix923[ansix923.size()-1] = ansix923.size();
			if(result.right(ansix923.size()) == ansix923)
				result.resize(result.size() - ansix923.size());
		}

		if(mime == MIME_ZLIB)
		{
			// Add size header for qUncompress compatibilty
			unsigned int origsize = std::max<int>(properties["OriginalSize"].toUInt(), 1);
			QByteArray size(4, 0);
			size[0] = (origsize & 0xff000000) >> 24;
			size[1] = (origsize & 0x00ff0000) >> 16;
			size[2] = (origsize & 0x0000ff00) >> 8;
			size[3] = (origsize & 0x000000ff);
			result = qUncompress(size + result);
			mime = properties["OriginalMimeType"];
		}

		if(mime == MIME_DDOC || mime == MIME_DDOC_OLD)
		{
			ddoc = new QTemporaryFile( QDir().tempPath() + "/XXXXXX" );
			if( !ddoc->open() )
			{
				lastError = CryptoDoc::tr("Failed to create temporary files<br />%1").arg( ddoc->errorString() );
				return;
			}
			ddoc->write(result);
			ddoc->flush();
			ddoc->reset();
			readDDoc(ddoc);
		}
		else
		{
			if(!files.isEmpty())
				files[0].data = result;
			else if(properties.contains("Filename"))
			{
				File f;
				f.name = properties["Filename"];
				f.mime = mime;
				f.size = FileDialog::fileSize(result.size());
				f.data = result;
				files << f;
			}
			else
				lastError = CryptoDoc::tr("Error parsing document");
		}
	}
	encrypted = !encrypted;
}

void CryptoDocPrivate::setLastError( const QString &err )
{
	QMessageBox d( QMessageBox::Warning, CryptoDoc::tr("DigiDoc3 crypto"),
		err, QMessageBox::Close, qApp->activeWindow() );
}

QByteArray CryptoDocPrivate::readCDoc(QIODevice *cdoc, bool data)
{
	QXmlStreamReader xml(cdoc);

	if(!data)
	{
		files.clear();
		keys.clear();
		properties.clear();
		method.clear();
		mime.clear();
	}
	while( !xml.atEnd() )
	{
		if( !xml.readNextStartElement() )
			continue;
		if(data)
		{
			// EncryptedData/KeyInfo
			if(xml.name() == "KeyInfo")
				xml.skipCurrentElement();
			// EncryptedData/CipherData/CipherValue
			else if(xml.name() == "CipherValue")
			{
				xml.readNext();
				QStringRef ref = xml.text();
				QByteArray result(ref.size(), Qt::Uninitialized);
				QString buf(64, Qt::Uninitialized);
				int offsetResult = 0, offsetBuf = 0;
				for(int i = 0; i < ref.size(); ++i)
				{
					QChar c = ref.data()[i];
					if(c.isLetterOrNumber() || c == '+' || c == '/' || c == '=')
						buf[offsetBuf++] = c;
					if(offsetBuf == 64)
					{
						QByteArray b64 = QByteArray::fromBase64(buf.toAscii());
						for(int j = 0; j < b64.size(); j++)
							result[offsetResult++] = b64[j];
						offsetBuf = 0;
					}
				}
				buf.truncate(offsetBuf);
				QByteArray b64 = QByteArray::fromBase64(buf.toAscii());
				for(int j = 0; j < b64.size(); j++)
					result[offsetResult++] = b64[j];
				result.truncate(offsetResult);
				return result;
			}
			continue;
		}

		// EncryptedData
		else if( xml.name() == "EncryptedData")
			mime = xml.attributes().value("MimeType").toString();
		// EncryptedData/EncryptionProperties/EncryptionProperty
		else if( xml.name() == "EncryptionProperty" )
		{
			for( const QXmlStreamAttribute &attr: xml.attributes() )
			{
				if( attr.name() != "Name" )
					continue;
				if( attr.value() == "orig_file" )
				{
					QStringList fileparts = xml.readElementText().split("|");
					File file;
					file.name = fileparts.value(0);
					file.size = size(fileparts.value(1));
					file.mime = fileparts.value(2);
					file.id = fileparts.value(3);
					files << file;
				}
				else
					properties[attr.value().toString()] = xml.readElementText();
			}
		}
		// EncryptedData/EncryptionMethod
		else if( xml.name() == "EncryptionMethod" )
			method = xml.attributes().value("Algorithm").toString();
		// EncryptedData/KeyInfo/EncryptedKey
		else if( xml.name() == "EncryptedKey" )
		{
			CKey key;
			key.id = xml.attributes().value("Id").toString();
			key.recipient = xml.attributes().value("Recipient").toString();
			while(!xml.atEnd())
			{
				xml.readNext();
				if( xml.name() == "EncryptedKey" && xml.isEndElement() )
					break;
				if( !xml.isStartElement() )
					continue;
				// EncryptedData/KeyInfo/KeyName
				if(xml.name() == "KeyName")
					key.name = xml.readElementText();
				// EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod
				else if(xml.name() == "EncryptionMethod")
					key.method = xml.attributes().value("Algorithm").toString();
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/X509Data/X509Certificate
				else if(xml.name() == "X509Certificate")
				{
					xml.readNext();
					key.cert = QSslCertificate( QByteArray::fromBase64( xml.text().toUtf8() ), QSsl::Der );
				}
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/CipherData/CipherValue
				else if(xml.name() == "CipherValue")
				{
					xml.readNext();
					key.chipher = QByteArray::fromBase64( xml.text().toUtf8() );
				}
			}
			keys << key;
		}
	}
	return QByteArray();
}

void CryptoDocPrivate::writeCDoc(QIODevice *cdoc, const QByteArray &key, const QByteArray &data, const QString &file, const QString &ver, const QString &mime)
{
	QHash<QString,QString> props;
	props["DocumentFormat"] = "ENCDOC-XML|" + ver;
	props["LibraryVersion"] = qApp->applicationName() + "|" + qApp->applicationVersion();
	props["Filename"] = file;

	static const QString DS = "http://www.w3.org/2000/09/xmldsig#";
	static const QString DENC = "http://www.w3.org/2001/04/xmlenc#";

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
		if(!k.name.isEmpty())
			w.writeTextElement(DS, "KeyName", k.name);
		w.writeStartElement(DS, "X509Data");
		writeBase64(w, DS, "X509Certificate", k.cert.toDer());
		w.writeEndElement(); //X509Data
		w.writeEndElement(); //KeyInfo
		w.writeStartElement(DENC, "CipherData");

		RSA *rsa = (RSA*)k.cert.publicKey().handle();
		QByteArray chipper(RSA_size(rsa), 0);
		RSA_public_encrypt(key.size(), (unsigned char*)key.constData(), (unsigned char*)chipper.data(), rsa, RSA_PKCS1_PADDING);
		writeBase64(w, DENC, "CipherValue", chipper);
		w.writeEndElement(); //CipherData
		w.writeEndElement(); //EncryptedKey
	}
	w.writeEndElement(); //KeyInfo

	w.writeStartElement(DENC, "CipherData");
	writeBase64(w, DENC, "CipherValue", data);
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
			hasSignature = true;
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

	for(const File &file: files)
	{
		x.writeStartElement("DataFile");
		x.writeAttribute("ContentType", "EMBEDDED_BASE64");
		x.writeAttribute("Filename", file.name);
		x.writeAttribute("Id", file.id);
		x.writeAttribute("MimeType", file.mime);
		x.writeAttribute("Size", QString::number(file.data.size()));
		x.writeDefaultNamespace("http://www.sk.ee/DigiDoc/v1.3.0#");
		for(int i = 0; i < file.data.size(); i+=48)
			x.writeCharacters(file.data.mid(i, 48).toBase64() + "\n");
		x.writeEndElement(); //DataFile
	}

	x.writeEndElement(); //SignedDoc
	x.writeEndDocument();
}



CDocumentModel::CDocumentModel( CryptoDocPrivate *doc )
:	QAbstractTableModel( doc )
,	d( doc )
{
	setSupportedDragActions( Qt::CopyAction );
}

void CDocumentModel::addFile( const QString &file, const QString &mime )
{
	if( d->isEncryptedWarning() )
		return;

	emit beginInsertRows(QModelIndex(), d->files.size(), 1);
	QFile data(file);
	data.open(QFile::ReadOnly);
	CryptoDocPrivate::File f;
	f.id = QString("D%1").arg(d->files.size());
	f.mime = mime;
	f.name = QFileInfo(file).fileName();
	f.data = data.readAll();
	f.size = FileDialog::fileSize(f.data.size());
	d->files << f;
	emit endInsertRows();
}

int CDocumentModel::columnCount( const QModelIndex &parent ) const
{ return parent.isValid() ? 0 : NColumns; }

QString CDocumentModel::copy( const QModelIndex &index, const QString &path ) const
{
	const CryptoDocPrivate::File &row = d->files.value( index.row() );
	if( row.name.isEmpty() )
		return QString();
	QString dst = QFileInfo( path ).isDir() ? mkpath( index, path ) : path;
	if( QFile::exists( dst ) )
		QFile::remove( dst );

	QFile f(dst);
	if(!f.open(QFile::WriteOnly) || f.write(row.data) < 0)
	{
		d->setLastError( tr("Failed to save file '%1'").arg( dst ) );
		return QString();
	}
	return dst;
}

QVariant CDocumentModel::data( const QModelIndex &index, int role ) const
{
	const CryptoDocPrivate::File &f = d->files.value( index.row() );
	if( f.name.isEmpty() )
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
		case Name: return f.name;
		case Mime: return f.mime;
		case Size: return f.size;
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
			.arg( f.name, f.size, f.mime );
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
	case Qt::UserRole: return f.id;
	default: return QVariant();
	}
}

Qt::ItemFlags CDocumentModel::flags( const QModelIndex & ) const
{
	return !d->encrypted ? Qt::ItemIsEnabled|Qt::ItemIsSelectable|Qt::ItemIsDragEnabled : Qt::NoItemFlags;
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
	QString filename = d->files.value( index.row() ).name;
#if defined(Q_OS_WIN)
	filename.replace( QRegExp( "[\\\\/*:?\"<>|]" ), "_" );
#elif defined(Q_OS_MAC)
	filename.replace( QRegExp( "[\\\\/:]"), "_" );
#else
	filename.replace( QRegExp( "[\\\\/]"), "_" );
#endif
	return path.isEmpty() ? filename : path + "/" + filename;
}

void CDocumentModel::open( const QModelIndex &index )
{
	if(d->encrypted)
		return;
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
#else
	QFile::setPermissions( f.absoluteFilePath(), QFile::Permissions(0x6000) );
#endif
	QDesktopServices::openUrl( QUrl::fromLocalFile( f.absoluteFilePath() ) );
}

bool CDocumentModel::removeRows( int row, int count, const QModelIndex &parent )
{
	if( parent.isValid() || d->isEncryptedWarning() )
		return false;

	if( d->files.isEmpty() || row >= d->files.size() )
	{
		d->setLastError( tr("Internal error") );
		return false;
	}

	beginRemoveRows( parent, row, row + count );
	for( int i = row + count - 1; i >= row; --i )
		d->files.removeAt( i );
	endRemoveRows();
	return true;
}

int CDocumentModel::rowCount( const QModelIndex &parent ) const
{ return parent.isValid() ? 0 : d->files.size(); }



void CKey::setCert( const QSslCertificate &c )
{
	cert = c;
	recipient = SslCertificate(c).friendlyName();
}



CryptoDoc::CryptoDoc( QObject *parent )
:	QObject( parent )
,	d( new CryptoDocPrivate )
{
	d->documents = new CDocumentModel( d );
}

CryptoDoc::~CryptoDoc() { clear(); delete d; }

bool CryptoDoc::addKey( const CKey &key )
{
	if( d->isEncryptedWarning() )
		return false;
	if( d->keys.contains( key ) )
	{
		d->setLastError( tr("Key already exists") );
		return false;
	}
	d->keys << key;
	return true;
}

void CryptoDoc::clear( const QString &file )
{
	delete d->ddoc;
	d->ddoc = nullptr;
	d->hasSignature = false;
	d->encrypted = false;
	d->fileName = file;
	d->files.clear();
	d->keys.clear();
	d->properties.clear();
	d->method.clear();
	d->mime.clear();
}

bool CryptoDoc::decrypt()
{
	if( d->fileName.isEmpty() )
	{
		d->setLastError( tr("Container is not open") );
		return false;
	}
	if( !d->encrypted )
		return true;

	CKey key;
	for(const CKey &k: d->keys)
	{
		if( qApp->signer()->tokenauth().cert() == k.cert )
		{
			key = k;
			break;
		}
	}
	if( key.cert.isNull() )
	{
		d->setLastError( tr("You do not have the key to decrypt this document") );
		return false;
	}

	bool decrypted = false;
	while( !decrypted )
	{
		switch( qApp->signer()->decrypt( key.chipher, d->key ) )
		{
		case QSigner::DecryptOK: decrypted = true; break;
		case QSigner::PinIncorrect: break;
		default: return false;
		}
	}

	d->waitForFinished();
	if( !d->lastError.isEmpty() )
		d->setLastError( d->lastError );
	d->documents->revert();
	return !d->encrypted;
}

CDocumentModel* CryptoDoc::documents() const { return d->documents; }

bool CryptoDoc::encrypt( const QString &filename )
{
	if( !filename.isEmpty() )
		d->fileName = filename;
	if( d->fileName.isEmpty() )
	{
		d->setLastError( tr("Container is not open") );
		return false;
	}
	if( d->encrypted )
		return true;
	if( d->keys.isEmpty() )
	{
		d->setLastError( tr("No keys specified") );
		return false;
	}

	d->waitForFinished();
	if( !d->lastError.isEmpty() )
		d->setLastError( d->lastError );
	open(d->fileName);
	return d->encrypted;
}

QString CryptoDoc::fileName() const { return d->fileName; }
bool CryptoDoc::isEncrypted() const { return d->encrypted; }
bool CryptoDoc::isNull() const { return d->fileName.isEmpty(); }
bool CryptoDoc::isSigned() const { return d->hasSignature; }

QList<CKey> CryptoDoc::keys()
{
	return d->keys;
}

bool CryptoDoc::open( const QString &file )
{
	clear(file);
	QFile cdoc(d->fileName);
	cdoc.open(QFile::ReadOnly);
	d->readCDoc(&cdoc, false);
	cdoc.close();

	if(d->files.isEmpty() && d->properties.contains("Filename"))
	{
		CryptoDocPrivate::File f;
		f.name = d->properties["Filename"];
		f.mime = d->mime == MIME_ZLIB ? d->properties["OriginalMimeType"] : d->mime;
		f.size = d->size(d->properties["OriginalSize"]);
		d->files << f;
	}

	d->encrypted = true;
	d->documents->revert();
	qApp->addRecent( file );
	return !d->keys.isEmpty();
}

void CryptoDoc::removeKey( int id )
{
	if( !d->isEncryptedWarning() )
		d->keys.removeAt(id);
}

bool CryptoDoc::saveDDoc( const QString &filename )
{
	if( !d->ddoc )
	{
		d->setLastError( tr("Document not open") );
		return false;
	}

	bool result = d->ddoc->copy( filename );
	if( !result )
		d->setLastError( tr("Failed to save file") );
	return result;
}

#include "CryptoDoc.moc"
