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

#include <common/SslCertificate.h>
#include <common/TokenData.h>

#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtGui/QDesktopServices>
#if QT_VERSION >= 0x050000
#include <QtWidgets/QLabel>
#else
#include <QtGui/QLabel>
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
	if( identity )
	{
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
	}
#endif
	return PKCS12Certificate::fromPath(
		Application::confValue( Application::PKCS12Cert ).toString(),
		Application::confValue( Application::PKCS12Pass ).toString() ).certificate();
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
	if( identity )
	{
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
	}
#endif
	return PKCS12Certificate::fromPath(
		Application::confValue( Application::PKCS12Cert ).toString(),
		Application::confValue( Application::PKCS12Pass ).toString() ).key();
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

bool AccessCert::validate()
{
	if( Application::confValue( Application::PKCS12Disable, false ).toBool() )
		return true;
#ifdef Q_OS_MAC
	QSslCertificate c = cert();
#else
	d->cert = Application::confValue( Application::PKCS12Cert ).toString();
	d->pass = Application::confValue( Application::PKCS12Pass ).toString();

	QSslCertificate c;
	PKCS12Certificate p12 = PKCS12Certificate::fromPath( d->cert, d->pass );
	switch( p12.error() )
	{
	case PKCS12Certificate::NullError:
		c = p12.certificate();
		break;
	case PKCS12Certificate::FileNotExist:
	case PKCS12Certificate::FailedToRead:
	case PKCS12Certificate::InvalidPasswordError:
	case PKCS12Certificate::UnknownError:
	default:
		remove();
		return true;
	}
#endif
	if( !c.isNull() && c.subjectInfo("GN").isEmpty() && c.subjectInfo("SN").isEmpty() )
	{
		if( !c.isValid() )
		{
			showWarning( QString("%1<br />%2").arg( tr("Server access certificate is not valid!"), link() ) );
			return false;
		}
		else if( c.expiryDate() < QDateTime::currentDateTime().addDays( 8 ) )
		{
			showWarning( QString("%1<br />%2").arg( tr("Server access certificate is about to expire!"), link() ) );
			return true;
		}
	}

	remove();
	return true;
}
