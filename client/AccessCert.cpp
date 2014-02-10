/*
 * QDigiDocClient
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

#include "AccessCert.h"

#include "Application.h"
#include "QSigner.h"

#ifdef Q_OS_WIN
#include <common/QCNG.h>
#endif
#include <common/QPKCS11.h>
#include <common/SslCertificate.h>
#include <common/sslConnect.h>
#include <common/TokenData.h>

#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QScopedPointer>
#include <QtCore/QUrl>
#include <QtCore/QXmlStreamReader>
#include <QtGui/QDesktopServices>
#if QT_VERSION >= 0x050000
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#else
#include <QtGui/QLabel>
#include <QtGui/QPushButton>
#endif
#include <QtNetwork/QSslKey>

#ifdef Q_OS_MAC
#include <Security/Security.h>
#include <Security/SecItem.h>
#endif

class AccessCertPrivate
{
public:
	QString cert, pass;
};

AccessCert::AccessCert( QWidget *parent )
:	QMessageBox( parent )
,	d( new AccessCertPrivate )
{
	setWindowTitle( tr("Server access certificate") );
	if( QLabel *label = findChild<QLabel*>() )
		label->setOpenExternalLinks( true );
#ifndef Q_OS_MAC
	d->cert = Application::confValue( Application::PKCS12Cert ).toString();
	d->pass = Application::confValue( Application::PKCS12Pass ).toString();
#endif
}

AccessCert::~AccessCert()
{
#ifndef Q_OS_MAC
	Application::setConfValue( Application::PKCS12Cert, d->cert );
	Application::setConfValue( Application::PKCS12Pass, d->pass );
#endif
	delete d;
}

QSslCertificate AccessCert::cert()
{
#ifdef Q_OS_MAC
	SecIdentityRef identity = 0;
	OSStatus err = SecIdentityCopyPreference( CFSTR("ocsp.sk.ee"), 0, 0, &identity );
	if( !identity )
		return QSslCertificate();

	SecCertificateRef certref = 0;
	err = SecIdentityCopyCertificate( identity, &certref );
	CFRelease( identity );
	if( !certref )
		return QSslCertificate();

	CFDataRef certdata = SecCertificateCopyData( certref );
	CFRelease( certref );
	if( !certdata )
		return QSslCertificate();

	QSslCertificate cert(
		QByteArray( (const char*)CFDataGetBytePtr( certdata ), CFDataGetLength( certdata ) ), QSsl::Der );
	CFRelease( certdata );
	return cert;
#else
	return PKCS12Certificate::fromPath(
		Application::confValue( Application::PKCS12Cert ).toString(),
		Application::confValue( Application::PKCS12Pass ).toString() ).certificate();
#endif
}

bool AccessCert::download( bool noCard )
{
	if( noCard )
	{
		QDesktopServices::openUrl( QUrl( tr("http://www.sk.ee/toend/") ) );
		return false;
	}

	if( SslCertificate( qApp->signer()->tokensign().cert() ).type() & SslCertificate::TempelType )
	{
		setIcon( Information );
		setText( tr("For getting server access certificate to Tempel contact <a href=\"mailto:sales@sk.ee\">sales@sk.ee</a>") );
		return false;
	}

	setIcon( Information );
	setText(
		tr("Hereby I agree to terms and conditions of validity confirmation service and "
		   "will use the service in extent of 10 signatures per month. If you going to "
		   "exceed the limit of 10 signatures per month or/and will use the service for "
		   "commercial purposes, please refer to IT support of your company. Additional "
		   "information is available from <a href=\"%1\">%1</a> or phone 1777")
			.arg( tr("http://www.id.ee/kehtivuskinnitus") ) );
	setStandardButtons( Help );
	QPushButton *agree = addButton( tr("Agree"), AcceptRole );
	if( exec() == Help )
	{
		QDesktopServices::openUrl( QUrl( tr("http://www.id.ee/kehtivuskinnitus") ) );
		return false;
	}
	removeButton( agree );

	QSigner *s = qApp->signer();
	QPKCS11 *p = qobject_cast<QPKCS11*>(s->handle());
#ifdef Q_OS_WIN
	QCNG *c = qobject_cast<QCNG*>(s->handle());
	if( !p && !c )
		return false;
#endif

	s->lock();
	Qt::HANDLE key = 0;
	TokenData token;
	if( p )
	{
		bool retry = false;
		do {
			retry = false;
			token.setCard( s->tokensign().card() );
			Q_FOREACH( const TokenData &t, p->tokens() )
				if( token.card() == t.card() && SslCertificate( t.cert() ).enhancedKeyUsage().contains( SslCertificate::ClientAuth ) )
					token.setCert( t.cert() );

			QPKCS11::PinStatus status = p->login( token );
			switch( status )
			{
			case QPKCS11::PinOK: break;
			case QPKCS11::PinCanceled:
				s->unlock();
				return false;
			case QPKCS11::PinIncorrect:
				showWarning( QPKCS11::errorString( status ) );
				retry = true;
				break;
			default:
				showWarning( tr("Error downloading server access certificate!") + "\n" + QPKCS11::errorString( status ) );
				s->unlock();
				return false;
			}
		} while( retry );
		key = p->key();
	}
	else
	{
#ifdef Q_OS_WIN
		QCNG::Certs certs = c->certs();
		for( QCNG::Certs::const_iterator i = certs.constBegin(); i != certs.constEnd(); ++i )
		{
			if( i.value() == s->tokensign().card() && i.key().isValid() &&
				i.key().enhancedKeyUsage().contains( SslCertificate::ClientAuth ) )

			{
				token = c->selectCert( i.key() );
				break;
			}
		}
		key = c->key();
#else
		s->unlock();
		return false;
#endif
	}

	SSLConnect ssl;
	ssl.setToken( token.cert(), key );
	QByteArray result = ssl.getUrl( SSLConnect::AccessCert );
	s->unlock();
	if( !ssl.errorString().isEmpty() )
	{
		showWarning( tr("Error downloading server access certificate!") + "\n" + ssl.errorString() );
		return false;
	}

	if( result.isEmpty() )
	{
		showWarning( tr("Empty result!") );
		return false;
	}

	QString status, cert, pass, message;
	QXmlStreamReader xml( result );
	while( xml.readNext() != QXmlStreamReader::Invalid )
	{
		if( !xml.isStartElement() )
			continue;
		if( xml.name() == "StatusCode" )
			status = xml.readElementText();
		else if( xml.name() == "MessageToDisplay" )
			message = xml.readElementText();
		else if( xml.name() == "TokenData" )
			cert = xml.readElementText();
		else if( xml.name() == "TokenPassword" )
			pass = xml.readElementText();
	}

	if( status.isEmpty() )
	{
		showWarning( tr("Error parsing server access certificate result!") );
		return false;
	}

	switch( status.toInt() )
	{
	case 1: //need to order cert manually from SK web
		QDesktopServices::openUrl( QUrl( tr("http://www.sk.ee/toend/") ) );
		return false;
	case 2: //got error, show message from MessageToDisplay element
		showWarning( tr("Error downloading server access certificate!\n%1").arg( message ) );
		return false;
	default: break; //ok
	}

	if( cert.isEmpty() )
	{
		showWarning( tr("Error reading server access certificate - empty content!") );
		return false;
	}

	return installCert( QByteArray::fromBase64( cert.toUtf8() ), pass );
}

bool AccessCert::installCert( const QByteArray &data, const QString &password )
{
#ifdef Q_OS_MAC
	CFDataRef pkcs12data = CFDataCreate( 0, (const UInt8*)data.constData(), data.size() );

	SecExternalFormat format = kSecFormatPKCS12;
	SecExternalItemType type = kSecItemTypeAggregate;

	SecKeyImportExportParameters params;
	memset( &params, 0, sizeof(params) );
	params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
	params.flags = kSecKeyImportOnlyOne|kSecKeyNoAccessControl;
	params.keyAttributes = CSSM_KEYATTR_PERMANENT|CSSM_KEYATTR_EXTRACTABLE;
	params.keyUsage = CSSM_KEYUSE_DECRYPT|CSSM_KEYUSE_UNWRAP|CSSM_KEYUSE_DERIVE;
	params.passphrase = CFStringCreateWithCharacters( 0,
		reinterpret_cast<const UniChar *>(password.unicode()), password.length() );

	SecKeychainRef keychain;
	SecKeychainCopyDefault( &keychain );
	CFArrayRef items = 0;
	OSStatus err = SecKeychainItemImport( pkcs12data, 0, &format, &type, 0, &params, keychain, &items );
	CFRelease( pkcs12data );
	CFRelease( params.passphrase );

	if( err != errSecSuccess )
	{
		showWarning( tr("Failed to save server access certificate file to KeyChain!") );
		return false;
	}

	SecIdentityRef identity = 0;
	for( CFIndex i = 0; i < CFArrayGetCount( items ); ++i )
	{
		CFTypeRef item = CFTypeRef(CFArrayGetValueAtIndex( items, i ));
		if( CFGetTypeID( item ) == SecIdentityGetTypeID() )
			identity = SecIdentityRef(item);
	}

	err = SecIdentitySetPreference( identity, CFSTR("ocsp.sk.ee"), 0 );
	CFRelease( items );
	if( err != errSecSuccess )
	{
		showWarning( tr("Failed to save server access certificate file to KeyChain!") );
		return false;
	}
#else
	QString path = QDesktopServices::storageLocation( QDesktopServices::DataLocation );
	if ( !QDir( path ).exists() )
		QDir().mkpath( path );

	QFile f( QString( "%1/%2.p12" ).arg( path,
		SslCertificate( qApp->signer()->tokensign().cert() ).subjectInfo( "serialNumber" ) ) );
	if ( !f.open( QIODevice::WriteOnly|QIODevice::Truncate ) )
	{
		showWarning( tr("Failed to save server access certificate file to %1!\n%2")
			.arg( f.fileName() )
			.arg( f.errorString() ) );
		return false;
	}
	f.write( data );
	f.close();

	Application::setConfValue( Application::PKCS12Cert, d->cert = f.fileName() );
	Application::setConfValue( Application::PKCS12Pass, d->pass = password );
#endif
	return true;
}

QSslKey AccessCert::key()
{
#ifdef Q_OS_MAC
	SecIdentityRef identity = 0;
	OSStatus err = SecIdentityCopyPreference( CFSTR("ocsp.sk.ee"), 0, 0, &identity );
	if( !identity )
		return QSslKey();

	SecKeyRef keyref = 0;
	err = SecIdentityCopyPrivateKey( identity, &keyref );
	CFRelease( identity );
	if( !keyref )
		return QSslKey();

	CFDataRef keydata = 0;
	SecKeyImportExportParameters params;
	memset( &params, 0, sizeof(params) );
	params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
	params.passphrase = CFSTR("pass");
	err = SecKeychainItemExport( keyref, kSecFormatPEMSequence, 0, &params, &keydata );
	CFRelease( keyref );

	if( !keydata )
		return QSslKey();

	QSslKey key( QByteArray( (const char*)CFDataGetBytePtr(keydata), CFDataGetLength(keydata) ),
		QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey, "pass" );
	CFRelease( keydata );

	return key;
#else
	return PKCS12Certificate::fromPath(
		Application::confValue( Application::PKCS12Cert ).toString(),
		Application::confValue( Application::PKCS12Pass ).toString() ).key();
#endif
}

QString AccessCert::link() const
{
	return tr("<a href=\"http://www.id.ee/index.php?id=34321\">Find out what is server access certificate</a>.<br />");
}

void AccessCert::remove()
{
#ifdef Q_OS_MAC
	SecIdentityRef identity = 0;
	OSStatus err = SecIdentityCopyPreference( CFSTR("ocsp.sk.ee"), 0, 0, &identity );
	if( !identity )
		return;

	SecCertificateRef certref = 0;
	SecKeyRef keyref = 0;
	err = SecIdentityCopyCertificate( identity, &certref );
	err = SecIdentityCopyPrivateKey( identity, &keyref );
	CFRelease( identity );
	err = SecKeychainItemDelete( SecKeychainItemRef(certref) );
	err = SecKeychainItemDelete( SecKeychainItemRef(keyref) );
	CFRelease( certref );
	CFRelease( keyref );
#else
	d->cert.clear();
	d->pass.clear();
	Application::setConfValue( Application::PKCS12Cert, QVariant() );
	Application::setConfValue( Application::PKCS12Pass, QVariant() );
#endif
}

void AccessCert::showWarning( const QString &msg )
{
	setIcon( Warning );
	setText( msg );
	setStandardButtons( Ok );
	exec();
}

bool AccessCert::showWarning2( const QString &msg )
{
	setIcon( Warning );
	setText( msg );
	setStandardButtons( Yes | No );
	setDefaultButton( Yes );
	exec();
	return standardButton(clickedButton()) == No;
}

bool AccessCert::validate()
{
	if( Application::confValue( Application::PKCS12Disable, false ).toBool() )
		return true;
#ifdef Q_OS_MAC
	QSslCertificate c = cert();
	if( c.isNull() )
		return showWarning2( tr("Did not find any server access certificate!<br />%1Start downloading?").arg( link() ) );
	if( !c.isValid() )
		return showWarning2( tr("Server access certificate is not valid!<br />%1Start downloading?").arg( link() ) );
	if( c.expiryDate() < QDateTime::currentDateTime().addDays( 8 ) )
		return showWarning2( tr("Server access certificate is about to expire!<br />%1Start downloading?").arg( link() ) );
	return true;
#else
	d->cert = Application::confValue( Application::PKCS12Cert ).toString();
	d->pass = Application::confValue( Application::PKCS12Pass ).toString();

	PKCS12Certificate p12 = PKCS12Certificate::fromPath( d->cert, d->pass );
	switch( p12.error() )
	{
	case PKCS12Certificate::FileNotExist:
		if( showWarning2( tr("Did not find any server access certificate!<br />%1Start downloading?").arg( link() ) ) )
		{
			remove();
			return true;
		}
		break;
	case PKCS12Certificate::FailedToRead:
		if( showWarning2( tr("Failed to read server access certificate!<br />%1Start downloading?").arg( link() ) ) )
		{
			remove();
			return true;
		}
		break;
	case PKCS12Certificate::InvalidPasswordError:
		if( showWarning2( tr("Server access certificate password is not valid!<br />%1Start downloading?").arg( link() ) ) )
		{
			remove();
			return true;
		}
		break;
	case PKCS12Certificate::NullError:
		if( !p12.certificate().isValid() )
		{
			if( showWarning2( tr("Server access certificate is not valid!<br />%1Start downloading?").arg( link() ) ) )
			{
				remove();
				return true;
			}
		}
		else if( p12.certificate().expiryDate() < QDateTime::currentDateTime().addDays( 8 ) &&
			!showWarning2( tr("Server access certificate is about to expire!<br />%1Start downloading?").arg( link() ) ) )
			return false;
		else
			return true;
		break;
	case PKCS12Certificate::UnknownError:
	default:
		if( showWarning2( tr("Server access certificate is not valid!<br />%1Start downloading?").arg( link() ) ) )
		{
			remove();
			return true;
		}
		break;
	}
	return false;
#endif
}
