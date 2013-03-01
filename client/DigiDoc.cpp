/*
 * QDigiDocClient
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

#include "DigiDoc.h"

#include "Application.h"
#include "QSigner.h"

#include <common/FileDialog.h>
#include <common/SslCertificate.h>
#include <common/TokenData.h>

#include <digidocpp/DataFile.h>
#include <digidocpp/Signature.h>
#include <digidocpp/crypto/cert/X509Cert.h>

#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QMimeData>
#include <QtCore/QProcessEnvironment>
#include <QtCore/QStringList>
#include <QtCore/QUrl>
#include <QtGui/QDesktopServices>
#if QT_VERSION >= 0x050000
#include <QtWidgets/QMessageBox>
#else
#include <QtGui/QMessageBox>
#endif
#include <QtGui/QPixmap>

#include <stdexcept>


using namespace digidoc;

static std::string to( const QString &str ) { return std::string( str.toUtf8().constData() ); }
static QString from( const std::string &str ) { return QString::fromUtf8( str.c_str() ).normalized( QString::NormalizationForm_C ); }
static QByteArray fromVector( const std::vector<unsigned char> &d )
{ return d.empty() ? QByteArray() : QByteArray( (const char *)&d[0], d.size() ); }



DocumentModel::DocumentModel( DigiDoc *doc )
:	QAbstractTableModel( doc )
,	d( doc )
{
	setSupportedDragActions( Qt::CopyAction );
}

int DocumentModel::columnCount( const QModelIndex &parent ) const
{ return parent.isValid() ? 0 : NColumns; }

QString DocumentModel::copy( const QModelIndex &index, const QString &path ) const
{
	DataFile d = document( index );
	if( d.filePath().empty() )
		return QString();
	QString dst = mkpath( index, path );
	QFile::remove( dst );
	return QFile::copy( from( d.filePath() ), dst ) ? dst : QString();
}

QVariant DocumentModel::data( const QModelIndex &index, int role ) const
{
	DataFile d = document( index );
	if( d.filePath().empty() )
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
		case Id: return from( d.id() );
		case Name: return from( d.fileName() );
		case Mime: return from( d.mediaType() );
		case Size: return FileDialog::fileSize( QFileInfo( from( d.filePath() ) ).size() );
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
			.arg( from( d.fileName() ) )
			.arg( FileDialog::fileSize( QFileInfo( from( d.filePath() ) ).size() ) )
			.arg( from( d.mediaType() ) );
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
	case Qt::UserRole: return QFileInfo( from( d.filePath() ) ).absoluteFilePath();
	default: return QVariant();
	}
}

DataFile DocumentModel::document( const QModelIndex &index ) const
{
	if( !hasIndex( index.row(), index.column() ) )
		return DataFile( "", "" );

	try { return d->b->dataFiles().at( index.row() ); }
	catch( const Exception &e ) { d->setLastError( tr("Failed to get files from container"), e ); }
	return DataFile( "", "" );
}

Qt::ItemFlags DocumentModel::flags( const QModelIndex & ) const
{ return Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsDragEnabled; }

QMimeData* DocumentModel::mimeData( const QModelIndexList &indexes ) const
{
	QList<QUrl> list;
	Q_FOREACH( const QModelIndex &index, indexes )
	{
		if( index.column() != 0 )
			continue;
		QString path = copy( index, QDir::tempPath() );
		if( !path.isEmpty() )
			list << QUrl::fromLocalFile( QFileInfo( path ).absoluteFilePath() );
	}
	QMimeData *data = new QMimeData();
	data->setUrls( list );
	return data;
}

QStringList DocumentModel::mimeTypes() const
{ return QStringList() << "text/uri-list"; }

QString DocumentModel::mkpath( const QModelIndex &index, const QString &path ) const
{
	QString filename = from( document( index ).fileName() );
#if defined(Q_OS_WIN)
	filename.replace( QRegExp( "[\\\\/*:?\"<>|]" ), "_" );
#else
	filename.replace( QRegExp( "[\\\\]"), "_" );
#endif
	return path.isEmpty() ? filename : path + "/" + filename;
}

void DocumentModel::open( const QModelIndex &index )
{
	QFileInfo f( copy( index, QDir::tempPath() ) );
	if( !f.exists() )
		return;
#if defined(Q_OS_WIN)
	QStringList exts = QProcessEnvironment::systemEnvironment().value( "PATHEXT" ).split(';');
	exts << ".PIF" << ".SCR";
	if( exts.contains( "." + f.suffix(), Qt::CaseInsensitive ) &&
		QMessageBox::warning( qApp->activeWindow(), tr("DigiDoc3 client"),
			tr("This is an executable file! "
				"Executable files may contain viruses or other malicious code that could harm your computer. "
				"Are you sure you want to launch this file?"),
			QMessageBox::Yes|QMessageBox::No, QMessageBox::No ) == QMessageBox::No )
		return;
#endif
	QDesktopServices::openUrl( QUrl::fromLocalFile( f.absoluteFilePath() ) );
}

bool DocumentModel::removeRows( int row, int count, const QModelIndex &parent )
{
	if( !d->b || parent.isValid() )
		return false;

	try
	{
		beginRemoveRows( parent, row, row + count );
		for( int i = row + count - 1; i >= row; --i )
			d->b->removeDataFile( i );
		endRemoveRows();
		return true;
	}
	catch( const Exception &e ) { d->setLastError( tr("Failed remove document from container"), e ); }
	return false;
}

int DocumentModel::rowCount( const QModelIndex &parent ) const
{ return !d->b || parent.isValid() ? 0 : d->b->dataFiles().size(); }



DigiDocSignature::DigiDocSignature( const digidoc::Signature *signature, DigiDoc *parent )
:	s(signature)
,	m_lastErrorCode(-1)
,	m_parent(parent)
{}

QSslCertificate DigiDocSignature::cert() const
{
	QSslCertificate c;
	try
	{
		c = QSslCertificate( fromVector(s->signingCertificate()), QSsl::Der );
	}
	catch( const Exception & ) {}
	return c;
}

QDateTime DigiDocSignature::dateTime() const
{
	QDateTime date = ocspTime();
	return date.isNull() ? signTime() : date;
}

bool DigiDocSignature::isTest() const
{
	return SslCertificate( cert() ).type() & SslCertificate::TestType ||
		SslCertificate( ocspCert() ).type() & SslCertificate::TestType;
}

QString DigiDocSignature::lastError() const { return m_lastError; }
int DigiDocSignature::lastErrorCode() const { return m_lastErrorCode; }

QString DigiDocSignature::location() const
{
	QStringList l = locations();
	l.removeAll( "" );
	return l.join( ", " );
}

QStringList DigiDocSignature::locations() const
{
	return QStringList()
		<< from( s->city() ).trimmed()
		<< from( s->stateOrProvince() ).trimmed()
		<< from( s->postalCode() ).trimmed()
		<< from( s->countryName() ).trimmed();
}

QString DigiDocSignature::mediaType() const
{ return from( s->profile() ); }

QSslCertificate DigiDocSignature::ocspCert() const
{
	return QSslCertificate(
		fromVector(s->OCSPCertificate()), QSsl::Der );
}

QByteArray DigiDocSignature::ocspNonce() const
{
	return fromVector(s->nonce());
}

QDateTime DigiDocSignature::ocspTime() const
{
	QString dateTime = from( s->producedAt() );
	if( dateTime.isEmpty() )
		return QDateTime();
	QDateTime date = QDateTime::fromString( dateTime, "yyyy-MM-dd'T'hh:mm:ss'Z'" );
	date.setTimeSpec( Qt::UTC );
	return date;
}

DigiDoc* DigiDocSignature::parent() const { return m_parent; }

int DigiDocSignature::parseException( const digidoc::Exception &e ) const
{
	Q_FOREACH( const Exception &c, e.causes() )
	{
		int code = parseException( c );
		if( code != Exception::NoException )
			return code;
	}
	return e.code();
}

QString DigiDocSignature::role() const
{
	QStringList r = roles();
	r.removeAll( "" );
	return r.join( ", " );
}

QStringList DigiDocSignature::roles() const
{
	QStringList list;
	Q_FOREACH( const std::string &role, s->signerRoles() )
		list << from( role ).trimmed();
	return list;
}

void DigiDocSignature::setLastError( const Exception &e ) const
{
	QStringList causes;
	Exception::ExceptionCode code = Exception::NoException;
	int ddocError = -1;
	DigiDoc::parseException( e, causes, code, ddocError );
	m_lastError = causes.join( "\n" );
	m_lastErrorCode = ddocError;
}

QString DigiDocSignature::signatureMethod() const
{ return from( s->signatureMethod() ); }

QDateTime DigiDocSignature::signTime() const
{
	QString dateTime = from( s->signingTime() );
	if( dateTime.isEmpty() )
		return QDateTime();
	QDateTime date = QDateTime::fromString( dateTime, "yyyy-MM-dd'T'hh:mm:ss'Z'" );
	date.setTimeSpec( Qt::UTC );
	return date;
}

DigiDocSignature::SignatureType DigiDocSignature::type() const
{
	const std::string ver = s->profile();
	if( ver.compare( "signature/bdoc-1.0/TM" ) == 0 )
		return TMType;
	if( ver.compare( "signature/bdoc-1.0/TS" ) == 0 )
		return TSType;
	if( ver.compare( "signature/bdoc-1.0/BES" ) == 0 )
		return BESType;
	if( ver.compare( 0, 11, "DIGIDOC-XML" ) == 0 ||
		ver.compare( 0, 6, "SK-XML" ) == 0 )
		return DDocType;
	return UnknownType;
}

DigiDocSignature::SignatureStatus DigiDocSignature::validate() const
{
	try
	{
		s->validate();
		if( type() == BESType )
		{
			m_lastError = DigiDoc::tr("In the meaning of Estonian legislation this signature is not equivalent to handwritten signature.\n"
				"This signature is created in the BES format, using no certificate validity confimation nor timestamp.");
			return Invalid;
		}
		return Valid;
	}
	catch( const Exception &e )
	{
		setLastError( e );
		switch( parseException( e ) )
		{
		case Exception::CertificateIssuerMissing:
		case Exception::CertificateUnknown:
		case Exception::OCSPResponderMissing:
		case Exception::OCSPCertMissing: return Unknown;
		default: break;
		}
	}
	return Invalid;
}

bool DigiDocSignature::weakDigestMethod() const
{
	return s->isWeak() > 0;
}



DigiDoc::DigiDoc( QObject *parent )
:	QObject( parent )
,	b(0)
,	m_documentModel( new DocumentModel( this ) )
{}

DigiDoc::~DigiDoc() { clear(); }

void DigiDoc::addFile( const QString &file )
{
	if( !checkDoc( b->signatures().size() > 0, tr("Cannot add files to signed container") ) )
		return;
	try { b->addDataFile( to(file), "application/octet-stream" ); m_documentModel->reset(); }
	catch( const Exception &e ) { setLastError( tr("Failed add file to container"), e ); }
}

bool DigiDoc::addSignature( const QByteArray &signature )
{
	if( !checkDoc( b->dataFiles().size() == 0, tr("Cannot add signature to empty container") ) )
		return false;

	bool result = false;
	try
	{
		b->addRawSignature( std::vector<unsigned char>( signature.constData(), signature.constData() + signature.size() ) );
		result = true;
	}
	catch( const Exception &e ) { setLastError( tr("Failed to sign container"), e ); }
	return result;
}

bool DigiDoc::checkDoc( bool status, const QString &msg ) const
{
	if( isNull() )
		qApp->showWarning( tr("Container is not open") );
	else if( status )
		qApp->showWarning( msg );
	return !isNull() && !status;
}

void DigiDoc::clear()
{
	delete b;
	b = 0;
	m_fileName.clear();
	m_documentModel->reset();
}

void DigiDoc::create( const QString &file )
{
	clear();
	QString type = QFileInfo( file ).suffix().toLower();
	if( type == "bdoc" )
		b = new Container(Container::AsicType);
	else if( type == "ddoc" )
		b = new Container(Container::DDocType);
	m_fileName = file;
	m_documentModel->reset();
}

DocumentModel* DigiDoc::documentModel() const { return m_documentModel; }

QString DigiDoc::fileName() const { return m_fileName; }
bool DigiDoc::isNull() const { return b == 0; }
bool DigiDoc::isSupported() const
{
	std::string ver = b->mediaType();
	return ver.compare( 0, 6, "SK-XML" ) &&
		ver.compare( 0, 15, "DIGIDOC-XML/1.1" ) &&
		ver.compare( 0, 15, "DIGIDOC-XML/1.2" ) &&
		ver != "application/vnd.bdoc-1.0";
}

QString DigiDoc::newSignatureID() const
{
	SignatureList list = b->signatures();
	unsigned int id = 0;
	while(true)
	{
		bool found = false;
		for(SignatureList::const_iterator i = list.begin(); i != list.end(); ++i)
		{
			if((*i)->id().compare(QString("S%1").arg(id).toUtf8()))
			{
				found = true;
				break;
			}
		}
		if(!found)
			return QString("S%1").arg(id);
		++id;
	}
	return QString("S%1").arg(id);
}

bool DigiDoc::open( const QString &file )
{
	clear();
	try
	{
		b = new Container( to(file) );
		m_fileName = file;
		m_documentModel->reset();

		if( !isSupported() )
		{
			qApp->showWarning( tr(
				"The current file is a DigiDoc container that is not supported officially any longer.\n"
				"You are not allowed to add or remove signatures to this container.\n"
				"<a href='http://www.id.ee/index.php?id=36161'>Additional info</a>.") );
		}
		else if( documentType() != DDocType )
		{
			bool weak = false;
			Q_FOREACH( const Signature *s, b->signatures() )
			{
				if( !s->isWeak() )
					continue;
				weak = true;
				break;
			}
			if( weak )
				qApp->showWarning(
					tr("The current BDOC container uses weaker encryption method than officialy accepted in Estonia.") );
		} 
		qApp->addRecent( file );
		return true;
	}
	catch( const Exception &e )
	{ setLastError( tr("An error occurred while opening the document."), e ); }
	return false;
}

bool DigiDoc::parseException( const Exception &e, QStringList &causes,
	Exception::ExceptionCode &code, int &ddocError )
{
	causes << from( e.msg() );
	if( e.code() & Exception::DDocError )
		ddocError = e.code() & ~Exception::DDocError;
	switch( e.code() )
	{
	case Exception::CertificateRevoked:
	case Exception::CertificateUnknown:
	case Exception::OCSPTimeSlot:
	case Exception::OCSPRequestUnauthorized:
	case Exception::PINCanceled:
	case Exception::PINFailed:
	case Exception::PINIncorrect:
	case Exception::PINLocked:
		code = e.code();
		return false;
	default: break;
	}
	Q_FOREACH( const Exception &c, e.causes() )
		if( !parseException( c, causes, code, ddocError ) )
			return false;
	return true;
}

void DigiDoc::removeSignature( unsigned int num )
{
	if( !checkDoc( num >= b->signatures().size(), tr("Missing signature") ) )
		return;
	try { b->removeSignature( num ); }
	catch( const Exception &e ) { setLastError( tr("Failed remove signature from container"), e ); }
}

void DigiDoc::save( const QString &filename )
{
	/*if( !checkDoc() );
		return; */
	try
	{
		if( !filename.isEmpty() )
			m_fileName = filename;
		b->save( to(m_fileName) );
		qApp->addRecent( filename );
	}
	catch( const Exception &e ) { setLastError( tr("Failed to save container"), e ); }
}

void DigiDoc::setLastError( const QString &msg, const Exception &e )
{
	QStringList causes;
	Exception::ExceptionCode code = Exception::NoException;
	int ddocError = -1;
	parseException( e, causes, code, ddocError );
	switch( code )
	{
	case Exception::CertificateRevoked:
		qApp->showWarning( tr("Certificate status revoked"), ddocError, causes.join("\n") ); break;
	case Exception::CertificateUnknown:
		qApp->showWarning( tr("Certificate status unknown"), ddocError, causes.join("\n") ); break;
	case Exception::OCSPTimeSlot:
		qApp->showWarning( tr("Check your computer time"), ddocError, causes.join("\n") ); break;
	case Exception::OCSPRequestUnauthorized:
		qApp->showWarning( tr("Server access certificate is required"), ddocError, causes.join("\n") ); break;
	case Exception::PINCanceled:
		break;
	case Exception::PINFailed:
		qApp->showWarning( tr("PIN Login failed"), ddocError, causes.join("\n") ); break;
	case Exception::PINIncorrect:
		qApp->showWarning( tr("PIN Incorrect"), ddocError, causes.join("\n") ); break;
	case Exception::PINLocked:
		qApp->showWarning( tr("PIN Locked. Please use ID-card utility for PIN opening!"), ddocError, causes.join("\n") ); break;
	default:
		qApp->showWarning( msg, ddocError, causes.join("\n") ); break;
	}
}

bool DigiDoc::sign( const QString &city, const QString &state, const QString &zip,
	const QString &country, const QString &role, const QString &role2 )
{
	if( !checkDoc( b->dataFiles().size() == 0, tr("Cannot add signature to empty container") ) )
		return false;

	bool result = false;
	try
	{
		qApp->signer()->setSignatureProductionPlace(
			to(city), to(state), to(zip), to(country) );
		std::vector<std::string> roles;
		roles.push_back( to(role) );
		if ( !role2.isEmpty() )
			roles.push_back( to(role2) );
		qApp->signer()->setSignerRoles( roles );
		b->sign( qApp->signer() );
		result = true;
	}
	catch( const Exception &e )
	{
		QStringList causes;
		Exception::ExceptionCode code = Exception::NoException;
		int ddocError = -1;
		parseException( e, causes, code, ddocError );
		if( code == Exception::PINIncorrect )
		{
			qApp->showWarning( tr("PIN Incorrect") );
			if( !(qApp->signer()->token().flags() & TokenData::PinLocked) )
				return sign( city, state, zip, country, role, role2 );
		}
		else
			setLastError( tr("Failed to sign container"), e );
	}
	return result;
}

QList<DigiDocSignature> DigiDoc::signatures()
{
	QList<DigiDocSignature> list;
	if( !checkDoc() )
		return list;
	try
	{
		SignatureList signatures = b->signatures();
		for( SignatureList::const_iterator i = signatures.begin(); i != signatures.end(); ++i )
			list << DigiDocSignature( *i, this );
	}
	catch( const Exception &e ) { setLastError( tr("Failed to get signatures"), e ); }
	return list;
}

DigiDoc::DocumentType DigiDoc::documentType() const
{
	if( checkDoc() )
	{
		if( b->mediaType() == "application/vnd.etsi.asic-e+zip" ) return BDoc2Type;
		if( b->mediaType() == "application/vnd.bdoc-1.0" ) return BDocType;
	}
	return DDocType;
}

QByteArray DigiDoc::getFileDigest( unsigned int i ) const
{
	if( !checkDoc() )
		return QByteArray();

	try
	{
		DataFile file = m_documentModel->document( m_documentModel->index( i, DocumentModel::Name ) );
		return fromVector(file.calcDigest("http://www.w3.org/2000/09/xmldsig#sha1"));
	}
	catch( const Exception & ) {}

	return QByteArray();
}
