/*
 * QEstEidCommon
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

#include "sslConnect_p.h"

#include "PinDialog.h"
#include "Settings.h"
#include "SslCertificate.h"

#include <stdexcept>
#include <sstream>
#include <QApplication>
#include <QDateTime>
#include <QLocale>

#ifndef PKCS11_MODULE
#  if defined(_WIN32)
#    define PKCS11_MODULE "opensc-pkcs11.dll"
#  else
#    define PKCS11_MODULE "opensc-pkcs11.so"
#  endif
#endif

// PKCS#11
#define CKR_OK					(0)
#define CKR_CANCEL				(1)
#define CKR_FUNCTION_CANCELED	(0x50)
#define CKR_PIN_INCORRECT		(0xa0)
#define CKR_PIN_LOCKED			(0xa4)



class sslError: public std::runtime_error
{
public:
	sslError() : std::runtime_error("openssl error")
	{
		unsigned long err = ERR_get_error();
		std::ostringstream buf;
		buf << ERR_func_error_string( err ) << " (" << ERR_reason_error_string( err ) << ")";
		desc = buf.str();
	}
    ~sslError() throw () {}

	virtual const char *what() const throw() { return desc.c_str(); }
	void static check( bool result ) { if( !result ) throw sslError(); }

	std::string desc;
};



SSLThread::SSLThread( PKCS11_SLOT *slot, QObject *parent )
: QThread(parent), loginResult(CKR_OK), m_slot(slot) {}

SSLThread::~SSLThread() { wait(); }

void SSLThread::run()
{
	if( PKCS11_login( m_slot, 0, NULL ) < 0 )
		loginResult = ERR_GET_REASON( ERR_get_error() );
}



SSLConnectPrivate::SSLConnectPrivate()
:	unload( true )
,	p11( PKCS11_CTX_new() )
,	p11loaded( false )
,	sctx( NULL )
,	ssl( NULL )
,	reader( -1 )
,	nslots( 0 )
,	error( SSLConnect::UnknownError )
{}

SSLConnectPrivate::~SSLConnectPrivate()
{
	if( ssl )
	{
		SSL_shutdown( ssl );
		SSL_free( ssl );
	}
	SSL_CTX_free( sctx );
	if( nslots )
		PKCS11_release_all_slots( p11, pslots, nslots );
	if( unload )
		PKCS11_CTX_unload( p11 );
	PKCS11_CTX_free( p11 );

	ERR_remove_state(0);
}

bool SSLConnectPrivate::connectToHost( SSLConnect::RequestType type )
{
	if( !p11loaded )
		throw std::runtime_error( errorString.toStdString() );

	if( PKCS11_enumerate_slots( p11, &pslots, &nslots ) || !nslots )
		throw std::runtime_error( SSLConnect::tr( "failed to list slots" ).toStdString() );

	// Find token
	PKCS11_SLOT *slot = 0;
	if( reader >= 0 )
	{
		if ( (unsigned int)reader*4 > nslots )
			throw std::runtime_error( SSLConnect::tr( "token failed" ).toStdString() );
		slot = &pslots[reader*4];
	}
	else
	{
		for( unsigned int i = 0; i < nslots; ++i )
		{
			if( (&pslots[i])->token &&
				card.contains( (&pslots[i])->token->serialnr ) )
			{
				slot = &pslots[i];
				break;
			}
		}
	}
	if( !slot || !slot->token )
		throw std::runtime_error( SSLConnect::tr("no token available").toStdString() );

	// Find token cert
	PKCS11_CERT *certs;
	unsigned int ncerts;
	if( PKCS11_enumerate_certs(slot->token, &certs, &ncerts) || !ncerts )
		throw std::runtime_error( SSLConnect::tr("no certificate available").toStdString() );
	PKCS11_CERT *authcert = &certs[0];
	if( !SslCertificate::fromX509( Qt::HANDLE(authcert->x509) ).isValid() )
		throw std::runtime_error( SSLConnect::tr("Certificate is not valid").toStdString() );

	// Login token
	if( slot->token->loginRequired )
	{
		PinDialog *p = new PinDialog(
			slot->token->secureLogin ? PinDialog::Pin1PinpadType : PinDialog::Pin1Type,
			SslCertificate::fromX509( Qt::HANDLE(authcert->x509) ), qApp->activeWindow() );
		p->setWindowModality( Qt::ApplicationModal );
		unsigned long err = CKR_OK;
		if( !slot->token->secureLogin )
		{
			QString validatePin;
			if( pin.isNull() )
			{
				if( !p->exec() )
				{
					p->deleteLater();
					throw std::runtime_error( "" );
				}
				validatePin = p->text();
				p->deleteLater();
				QCoreApplication::processEvents();
			}
			else
				validatePin = pin;
			if( PKCS11_login(slot, 0, validatePin.toUtf8()) < 0 )
			{
				pin = QString();
				err = ERR_GET_REASON( ERR_get_error() );
			}
			else
				pin = validatePin;
		}
		else
		{
			pin.clear();
			p->show();
			SSLThread *t = new SSLThread( slot );
			t->start();
			do
			{
				QCoreApplication::processEvents();
				t->wait( 1 );
			}
			while( t->isRunning() );
			delete p;
			err = t->loginResult;
			delete t;
		}
		switch( err )
		{
		case CKR_OK: break;
		case CKR_CANCEL:
		case CKR_FUNCTION_CANCELED:
			throw std::runtime_error( "" ); break;
		case CKR_PIN_INCORRECT:
			throw std::runtime_error( "PIN1Invalid" ); break;
		case CKR_PIN_LOCKED:
			throw std::runtime_error( "PINLocked" ); break;
		default:
			throw std::runtime_error( "PIN1Invalid" ); break;
		}
	}

	// Find token key
	PKCS11_KEY *authkey = PKCS11_find_key( authcert );
	if ( !authkey )
		throw std::runtime_error( SSLConnect::tr("no key matching certificate available").toStdString() );
	EVP_PKEY *pkey = PKCS11_get_private_key( authkey );

	sctx = SSL_CTX_new( SSLv23_client_method() );
	sslError::check( SSL_CTX_use_certificate(sctx, authcert->x509 ) );
	sslError::check( SSL_CTX_use_PrivateKey(sctx,pkey) );
	sslError::check( SSL_CTX_check_private_key(sctx) );
	sslError::check( SSL_CTX_set_mode( sctx, SSL_MODE_AUTO_RETRY ) );

	ssl = SSL_new( sctx );

	BIO *sock;
	switch( type )
	{
	case SSLConnect::AccessCert:
	case SSLConnect::MobileInfo: sock = BIO_new_connect( const_cast<char*>(SK) ); break;
	default: sock = BIO_new_connect( const_cast<char*>(EESTI) ); break;
	}

	BIO_set_conn_port( sock, "https" );
	if( BIO_do_connect( sock ) <= 0 )
		throw std::runtime_error( SSLConnect::tr( "Failed to connect to host. Are you connected to the internet?" ).toStdString() );

	SSL_set_bio( ssl, sock, sock );
	sslError::check( SSL_connect( ssl ) );

#ifdef Q_OS_MAC
#ifndef SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
#define SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION	0x0010
#endif
	ssl->s3->flags |= SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
#endif

	return true;
}

QByteArray SSLConnectPrivate::getRequest( const QString &request ) const
{
	QByteArray data = request.toUtf8();
	sslError::check( SSL_write( ssl, data.constData(), data.length() ) );

	int bytesRead = 0;
	char readBuffer[4096];
	QByteArray buffer;
	do
	{
		bytesRead = SSL_read( ssl, &readBuffer, 4096 );

		if( bytesRead <= 0 )
		{
			switch( SSL_get_error( ssl, bytesRead ) )
			{
			case SSL_ERROR_NONE:
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
			case SSL_ERROR_ZERO_RETURN: // Disconnect
				break;
			default:
				sslError::check( 0 );
				break;
			}
		}

		if( bytesRead > 0 )
			buffer += QByteArray( (const char*)&readBuffer, bytesRead );
	} while( bytesRead > 0 );

	int pos = buffer.indexOf( "\r\n\r\n" );
	return pos ? buffer.mid( pos + 4 ) : buffer;
}



SSLConnect::SSLConnect( QObject *parent )
:	QObject( parent )
,	d( new SSLConnectPrivate() )
{
	setPKCS11( PKCS11_MODULE );
}

SSLConnect::~SSLConnect() { delete d; }

QByteArray SSLConnect::getUrl( RequestType type, const QString &value )
{
	if( !d->connectToHost( type ) )
		return QByteArray();

	QString header;
	switch( type )
	{
	case AccessCert:
	{
		QString lang;
		switch( QLocale().language() )
		{
		case QLocale::English: lang = "en"; break;
		case QLocale::Russian: lang = "ru"; break;
		case QLocale::Estonian:
		default: lang = "et"; break;
		}

		QString request = QString(
			"<SOAP-ENV:Envelope"
			"	xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\""
			"	xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\""
			"	xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
			"	xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">"
			"<SOAP-ENV:Body>"
			"<m:GetAccessToken"
			"	xmlns:m=\"urn:GetAccessToken\""
			"	SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
			"<Language xsi:type=\"xsd:string\">%1</Language>"
			"<RequestTime xsi:type=\"xsd:string\" />"
			"<SoftwareName xsi:type=\"xsd:string\">DigiDoc3</SoftwareName>"
			"<SoftwareVersion xsi:type=\"xsd:string\" />"
			"</m:GetAccessToken>"
			"</SOAP-ENV:Body>"
			"</SOAP-ENV:Envelope>" )
			.arg( lang.toUpper() );
		header = QString(
			"POST /id/GetAccessTokenWSProxy/ HTTP/1.1\r\n"
			"Host: %1\r\n"
			"Content-Type: text/xml\r\n"
			"Content-Length: %2\r\n"
			"SOAPAction: \"\"\r\n"
			"Connection: close\r\n\r\n"
			"%3" )
			.arg( SK ).arg( request.size() ).arg( request );
		break;
	}
	case EmailInfo:
		header = "GET /idportaal/postisysteem.naita_suunamised HTTP/1.0\r\n\r\n";
		break;
	case ActivateEmails:
		header = QString( "GET /idportaal/postisysteem.lisa_suunamine?%1 HTTP/1.0\r\n\r\n" ).arg( value );
		break;
	case MobileInfo:
		header = value;
		break;
	case PictureInfo:
		header = "GET /idportaal/portaal.idpilt HTTP/1.0\r\n\r\n";
		break;
	default: return QByteArray();
	}
	return d->getRequest( header );
}

SSLConnect::ErrorType SSLConnect::error() const { return d->error; }
QString SSLConnect::errorString() const { return d->errorString; }
QString SSLConnect::pin() const { return d->pin; }
QByteArray SSLConnect::result() const { return d->result; }
void SSLConnect::setCard( const QString &card ) { d->card = card; }
void SSLConnect::setPin( const QString &pin ) { d->pin = pin; }
void SSLConnect::setPKCS11( const QString &pkcs11, bool unload )
{
	if( d->p11loaded && d->unload )
		PKCS11_CTX_unload( d->p11 );
	d->unload = unload;
	d->p11loaded = PKCS11_CTX_load( d->p11, pkcs11.toUtf8() ) == 0;
	if( !d->p11loaded )
	{
		d->error = UnknownError;
		d->errorString = tr("failed to load pkcs11 module '%1'").arg( pkcs11 );
	}
}
void SSLConnect::setReader( int reader ) { d->reader = reader; }

void SSLConnect::waitForFinished( RequestType type, const QString &value )
{
	try { d->result = getUrl( type, value ); }
	catch( const std::runtime_error &e )
	{
		if( qstrcmp( e.what(), "" ) == 0 )
		{
			d->error = SSLConnect::PinCanceledError;
			d->errorString = tr("PIN canceled");
		}
		else if( qstrcmp( e.what(), "PIN1Invalid" ) == 0 )
		{
			d->error = SSLConnect::PinInvalidError;
			d->errorString = tr("Invalid PIN");
		}
		else if( qstrcmp( e.what(), "PINLocked" ) == 0 )
		{
			d->error = SSLConnect::PinLocked;
			d->errorString = tr("Pin locked");
		}
		else
		{
			d->error = SSLConnect::UnknownError;
			d->errorString = e.what();
		}
		return;
	}
	d->error = SSLConnect::UnknownError;
	d->errorString.clear();
}
