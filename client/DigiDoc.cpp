/*
 * QDigiDocClient
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

#include "DigiDoc.h"

#include "common/SslCertificate.h"

#include "QMobileSigner.h"
#include "QSigner.h"

#include <digidocpp/Conf.h>
#include <digidocpp/DDoc.h>
#include <digidocpp/Document.h>
#include <digidocpp/SignatureTM.h>
#include <digidocpp/WDoc.h>
#include <digidocpp/crypto/cert/DirectoryX509CertStore.h>
#include <digidocpp/io/ZipSerialize.h>

#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QSettings>

#include <stdexcept>


using namespace digidoc;

DigiDocSignature::DigiDocSignature( const digidoc::Signature *signature, DigiDoc *parent )
:	s(signature)
,	m_parent(parent)
{}

QSslCertificate DigiDocSignature::cert() const
{
	QSslCertificate c;
	try
	{
		X509 *x509 = s->getSigningCertificate().getX509();
		c = SslCertificate::fromX509( Qt::HANDLE(x509) );
		X509_free( x509 );
	}
	catch( const Exception & ) {}
	return c;
}

QDateTime DigiDocSignature::dateTime() const
{
	QString dateTime;
	switch( type() )
	{
	case TMType:
		dateTime = QString::fromUtf8(
			static_cast<const SignatureTM*>(s)->getProducedAt().c_str() );
		break;
	case DDocType:
		dateTime = QString::fromUtf8(
			static_cast<const SignatureDDOC*>(s)->getProducedAt().c_str() );
		break;
	default: break;
	}

	if( dateTime.isEmpty() )
		dateTime = QString::fromUtf8( s->getSigningTime().c_str() );

	if( dateTime.isEmpty() )
		return QDateTime();

	QDateTime date = QDateTime::fromString( dateTime, "yyyy-MM-dd'T'hh:mm:ss'Z'" );
	date.setTimeSpec( Qt::UTC );
	return date.toLocalTime();
}

QString DigiDocSignature::digestMethod() const
{
	try
	{
		std::vector<unsigned char> data;
		std::string method;
		switch( type() )
		{
		case TMType:
			static_cast<const SignatureTM*>(s)->getRevocationOCSPRef( data, method );
			break;
		case DDocType:
			static_cast<const SignatureDDOC*>(s)->getRevocationOCSPRef( data, method );
			break;
		default: return QString();
		}
		return QString::fromUtf8( method.c_str() );
	}
	catch( const Exception & ) {}
	return QString();
}

QByteArray DigiDocSignature::digestValue() const
{
	try
	{
		std::vector<unsigned char> data;
		std::string method;
		switch( type() )
		{
		case TMType:
			static_cast<const SignatureTM*>(s)->getRevocationOCSPRef( data, method );
			break;
		case DDocType:
			static_cast<const SignatureDDOC*>(s)->getRevocationOCSPRef( data, method );
			break;
		default: return QByteArray();
		}
		if( data.size() > 0 )
			return QByteArray( (const char*)&data[0], data.size() );
	}
	catch( const Exception & ) {}
	return QByteArray();
}

QString DigiDocSignature::lastError() const { return m_lastError; }

QString DigiDocSignature::location() const
{
	QStringList l = locations();
	l.removeAll( "" );
	return l.join( ", " );
}

QStringList DigiDocSignature::locations() const
{
	QStringList l;
	const SignatureProductionPlace p = s->getProductionPlace();
	l << QString::fromUtf8( p.city.c_str() ).trimmed();
	l << QString::fromUtf8( p.stateOrProvince.c_str() ).trimmed();
	l << QString::fromUtf8( p.postalCode.c_str() ).trimmed();
	l << QString::fromUtf8( p.countryName.c_str() ).trimmed();
	return l;
}

QString DigiDocSignature::mediaType() const
{ return QString::fromUtf8( s->getMediaType().c_str() ); }

QSslCertificate DigiDocSignature::ocspCert() const
{
	try
	{
		switch( type() )
		{
		case TMType:
			return SslCertificate::fromX509( Qt::HANDLE(
				static_cast<const SignatureTM*>(s)->getOCSPCertificate().getX509()) );
		case DDocType:
			return SslCertificate::fromX509( Qt::HANDLE(
				static_cast<const SignatureDDOC*>(s)->getOCSPCertificate().getX509()) );
		default: return QSslCertificate();
		}
	}
	catch( const Exception & ) {}
		return QSslCertificate();
}

DigiDoc* DigiDocSignature::parent() const { return m_parent; }

int DigiDocSignature::parseException( const digidoc::Exception &e )
{
	Q_FOREACH( const Exception &c, e.getCauses() )
	{
		int code = parseException( c );
		if( code != Exception::NoException )
			return code;
	}
	return e.code();
}

void DigiDocSignature::parseExceptionStrings( const digidoc::Exception &e, QStringList &causes )
{
	causes << QString::fromUtf8( e.getMsg().c_str() );
	Q_FOREACH( const Exception &c, e.getCauses() )
		parseExceptionStrings( c, causes );
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
	const SignerRole::TRoles roles = s->getSignerRole().claimedRoles;
	SignerRole::TRoles::const_iterator i = roles.begin();
	for( ; i != roles.end(); ++i )
		list << QString::fromUtf8( i->data() ).trimmed();
	return list;
}

void DigiDocSignature::setLastError( const Exception &e )
{
	QStringList causes;
	parseExceptionStrings( e, causes );
	m_lastError = causes.join( "<br />" );
}

DigiDocSignature::SignatureType DigiDocSignature::type() const
{
	if( s->getMediaType().compare( "signature/bdoc-1.0/TM" ) == 0 )
		return TMType;
	if( s->getMediaType().compare( "signature/bdoc-1.0/TS" ) == 0 )
		return TSType;
	if( s->getMediaType().compare( "signature/bdoc-1.0/BES" ) == 0 )
		return BESType;
	if( s->getMediaType().compare( 0, 11, "DIGIDOC-XML" ) == 0 ||
		s->getMediaType().compare( 0, 6, "SK-XML" ) == 0 )
		return DDocType;
	return UnknownType;
}

DigiDocSignature::SignatureStatus DigiDocSignature::validate()
{
	try
	{
		s->validateOffline();
		if( type() == BESType )
		{
			switch( s->validateOnline() )
			{
			case OCSP::GOOD: return Valid;
			case OCSP::REVOKED: return Invalid;
			case OCSP::UNKNOWN: return Unknown;
			}
		}
		else
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



DigiDoc::DigiDoc( QObject *parent )
:	QObject( parent )
,	b(0)
,	m_signer(0)
{}

DigiDoc::~DigiDoc()
{
	delete m_signer;
	clear();
	X509CertStore::destroy();
	digidoc::terminate();
}

QString DigiDoc::activeCard() const { return m_card; }

void DigiDoc::addFile( const QString &file )
{
	if( !checkDoc( b->signatureCount() > 0, tr("Cannot add files to signed container") ) )
		return;
	try { b->addDocument( Document( file.toUtf8().constData(), "file" ) ); }
	catch( const Exception &e ) { setLastError( e ); }
}

bool DigiDoc::checkDoc( bool status, const QString &msg )
{
	if( isNull() )
		setLastError( tr("Container is not open") );
	else if( status )
		setLastError( msg );
	return !isNull() && !status;
}

void DigiDoc::clear()
{
	delete b;
	b = 0;
	m_fileName.clear();
	m_lastError.clear();
}

void DigiDoc::create( const QString &file )
{
	clear();
	QString type = QFileInfo( file ).suffix().toLower();
	if( type == "bdoc" )
	{
		b = new WDoc( WDoc::BDocType );
		m_fileName = file;
	}
	else if( type == "ddoc" )
	{
		b = new WDoc( WDoc::DDocType );
		m_fileName = file;
	}
}

void DigiDoc::dataChanged( const QStringList &cards, const QString &card,
	const QSslCertificate &sign )
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
	if( m_signCert != sign )
	{
		changed = true;
		m_signCert = sign;
	}
	if( changed )
		Q_EMIT dataChanged();
}

QList<Document> DigiDoc::documents()
{
	QList<Document> list;
	if( !checkDoc() )
		return list;
	try
	{
		unsigned int count = b->documentCount();
		for( unsigned int i = 0; i < count; ++i )
			list << b->getDocument( i );
	}
	catch( const Exception &e ) { setLastError( e ); }

	return list;
}

QString DigiDoc::fileName() const { return m_fileName; }

bool DigiDoc::init()
{
	try
	{
		digidoc::initialize();
		X509CertStore::init( new DirectoryX509CertStore() );
	}
	catch( const Exception &e ) { setLastError( e ); return false; }

	m_signer = new QSigner();
	connect( m_signer, SIGNAL(dataChanged(QStringList,QString,QSslCertificate)),
		SLOT(dataChanged(QStringList,QString,QSslCertificate)) );
	connect( m_signer, SIGNAL(error(QString)), SLOT(setLastError(QString)) );
	m_signer->start();
	return true;
}

bool DigiDoc::isNull() const { return b == 0; }
QString DigiDoc::lastError() const { return m_lastError; }

bool DigiDoc::open( const QString &file )
{
	clear();
	m_fileName = file;
	try
	{
		b = new WDoc( file.toUtf8().constData() );
		return true;
	}
	catch( const Exception &e )
	{
		QStringList causes;
		Exception::ExceptionCode code;
		parseException( e, causes, code );
		setLastError( tr("An error occurred while opening the document.<br />%1").arg( causes.join("\n") ) );
	}
	return false;
}

bool DigiDoc::parseException( const Exception &e, QStringList &causes, Exception::ExceptionCode &code )
{
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
		code = e.code(); return false;
	default:
		causes << QString::fromUtf8( e.getMsg().c_str() );
		break;
	}
	Q_FOREACH( const Exception &c, e.getCauses() )
		if( !parseException( c, causes, code ) )
			return false;
	return true;
}

QStringList DigiDoc::presentCards() const { return m_cards; }

void DigiDoc::removeDocument( unsigned int num )
{
	if( !checkDoc( num >= b->documentCount(), tr("Missing document") ) )
		return;
	try { b->removeDocument( num ); }
	catch( const Exception &e ) { setLastError( e ); }
}

void DigiDoc::removeSignature( unsigned int num )
{
	if( !checkDoc( num >= b->signatureCount(), tr("Missing signature") ) )
		return;
	try { b->removeSignature( num ); }
	catch( const Exception &e ) { setLastError( e ); }
}

void DigiDoc::save()
{
	/*if( !checkDoc() );
		return; */
	try
	{
		std::auto_ptr<ISerialize> s(new ZipSerialize(m_fileName.toUtf8().constData()));
		b->saveTo( s );
	}
	catch( const Exception &e ) { setLastError( e ); }
}

void DigiDoc::selectCard( const QString &card )
{ QMetaObject::invokeMethod( m_signer, "selectCard", Qt::QueuedConnection, Q_ARG(QString,card) ); }

QString DigiDoc::getConfValue( ConfParameter parameter, const QVariant &value )
{
	digidoc::Conf *i = NULL;
	try { i = digidoc::Conf::getInstance(); }
	catch( const Exception & ) { return value.toString(); }

	std::string r;
	switch( parameter )
	{
	case PKCS11Module: r = i->getPKCS11DriverPath(); break;
	case ProxyHost: r = i->getProxyHost(); break;
	case ProxyPort: r = i->getProxyPort(); break;
	case ProxyUser: r = i->getProxyUser(); break;
	case ProxyPass: r = i->getProxyPass(); break;
	case PKCS12Cert: r = i->getPKCS12Cert(); break;
	case PKCS12Pass: r = i->getPKCS12Pass(); break;
	default: break;
	}
	return r.empty() ? value.toString() : QString::fromStdString( r );
}

void DigiDoc::setConfValue( ConfParameter parameter, const QVariant &value )
{
	digidoc::Conf *i = NULL;
	try { i = digidoc::Conf::getInstance(); }
	catch( const Exception & ) { return; }

	const std::string v = value.toString().toStdString();
	switch( parameter )
	{
	case ProxyHost: i->setProxyHost( v ); break;
	case ProxyPort: i->setProxyPort( v ); break;
	case ProxyUser: i->setProxyUser( v ); break;
	case ProxyPass: i->setProxyPass( v ); break;
	case PKCS12Cert: i->setPKCS12Cert( v ); break;
	case PKCS12Pass: i->setPKCS12Pass( v ); break;
	default: break;
	}
}

void DigiDoc::setLastError( const Exception &e )
{
	QStringList causes;
	Exception::ExceptionCode code;
	parseException( e, causes, code );
	switch( code )
	{
	case Exception::CertificateRevoked:
		setLastError( tr("Certificate status revoked") ); break;
	case Exception::CertificateUnknown:
		setLastError( tr("Certificate status unknown") ); break;
	case Exception::OCSPTimeSlot:
		setLastError( tr("Check your computer time") ); break;
	case Exception::OCSPRequestUnauthorized:
		setLastError( tr("Server access certificate is required")); break;
	case Exception::PINCanceled:
		break;
	case Exception::PINFailed:
		setLastError( tr("PIN Login failed") ); break;
	case Exception::PINIncorrect:
		setLastError( tr("PIN Incorrect") ); break;
	case Exception::PINLocked:
		setLastError( tr("PIN Locked") ); break;
	default:
		setLastError( causes.join( "\n" ) ); break;
	}
}

void DigiDoc::setLastError( const QString &err ) { Q_EMIT error( m_lastError = err ); }

bool DigiDoc::sign( const QString &city, const QString &state, const QString &zip,
	const QString &country, const QString &role, const QString &role2 )
{
	if( !checkDoc( b->documentCount() == 0, tr("Cannot add signature to empty container") ) )
		return false;

	bool result = false;
	try
	{
		m_signer->setSignatureProductionPlace( SignatureProductionPlace(
			city.toUtf8().constData(),
			state.toUtf8().constData(),
			zip.toUtf8().constData(),
			country.toUtf8().constData() ) );
		SignerRole sRole( role.toUtf8().constData() );
		if ( !role2.isEmpty() )
			sRole.claimedRoles.push_back( role2.toUtf8().constData() );
		m_signer->setSignerRole( sRole );
		b->sign( m_signer, Signature::TM );
		result = true;
	}
	catch( const Exception &e )
	{
		QStringList causes;
		Exception::ExceptionCode code;
		parseException( e, causes, code );
		if( code == Exception::PINIncorrect )
		{
			setLastError( tr("PIN Incorrect") );
			return sign( city, state, zip, country, role, role2 );
		}
		else
			setLastError( e );
	}
	return result;
}

QSslCertificate DigiDoc::signCert() { return m_signCert; }
QSigner *DigiDoc::signer() const { return m_signer; }

bool DigiDoc::signMobile( const QString &fName )
{
	if( !checkDoc( b->documentCount() == 0, tr("Cannot add signature to empty container") ) )
		return false;

	bool result = false;
	try
	{
		b->sign( new digidoc::QMobileSigner( fName ), Signature::MOBILE );
		result = true;
	}
	catch( const Exception &e ) { setLastError( e ); }
	return result;
}

QList<DigiDocSignature> DigiDoc::signatures()
{
	QList<DigiDocSignature> list;
	if( !checkDoc() )
		return list;
	try
	{
		unsigned int count = b->signatureCount();
		for( unsigned int i = 0; i < count; ++i )
			list << DigiDocSignature( b->getSignature( i ), this );
	}
	catch( const Exception &e ) { setLastError( e ); }
	return list;
}

WDoc::DocumentType DigiDoc::documentType()
{ return checkDoc() ? b->documentType() : WDoc::BDocType; }

QByteArray DigiDoc::getFileDigest( unsigned int i )
{
	QByteArray result;
	if( !checkDoc() )
		return result;
	result.resize(20);
	b->getFileDigest( i, (unsigned char*)result.data() );
	return result;
}
