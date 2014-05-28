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
#include <QtCore/QSettings>
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
extern const CFTypeRef kSecAttrIsPermanent;
extern const CFTypeRef kSecAttrIsExtractable;
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
	setIcon( Warning );
	setStandardButtons( Ok );
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
	if( SecIdentityRef identity = SecIdentityCopyPreferred( CFSTR("ocsp.sk.ee"), 0, 0 ) )
	{
		SecCertificateRef certref = 0;
		SecIdentityCopyCertificate( identity, &certref );
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

void AccessCert::increment()
{
	QString date = "AccessCertUsage" + QDate::currentDate().toString("yyyyMM");
	QSettings s;
	s.setValue(date, s.value(date, 0).toUInt() + 1);
}

bool AccessCert::installCert( const QByteArray &data, const QString &password )
{
#ifdef Q_OS_MAC
	CFDataRef pkcs12data = CFDataCreateWithBytesNoCopy(nullptr,
		(const UInt8*)data.constData(), data.size(), kCFAllocatorNull);

	SecExternalFormat format = kSecFormatPKCS12;
	SecExternalItemType type = kSecItemTypeAggregate;

	SecItemImportExportKeyParameters params;
	memset( &params, 0, sizeof(params) );
	params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
	params.flags = kSecKeyImportOnlyOne|kSecKeyNoAccessControl;
	CFTypeRef keyAttributes[] = { kSecAttrIsPermanent, kSecAttrIsExtractable };
	params.keyAttributes = CFArrayCreate(nullptr,
		(const void **)keyAttributes, sizeof(keyAttributes) / sizeof(keyAttributes[0]), nullptr);
	CFTypeRef keyUsage[] = { kSecAttrCanDecrypt, kSecAttrCanUnwrap, kSecAttrCanDerive };
	params.keyUsage = CFArrayCreate(nullptr,
		(const void **)keyUsage, sizeof(keyUsage) / sizeof(keyUsage[0]), nullptr);
	params.passphrase = CFStringCreateWithCharacters( 0,
		reinterpret_cast<const UniChar *>(password.unicode()), password.length() );

	SecKeychainRef keychain;
	SecKeychainCopyDefault( &keychain );
	CFArrayRef items = 0;
	OSStatus err = SecItemImport( pkcs12data, 0, &format, &type, 0, &params, keychain, &items );
	CFRelease( pkcs12data );
	CFRelease( params.passphrase );
	CFRelease( params.keyUsage );
	CFRelease( params.keyAttributes );

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

	err = SecIdentitySetPreferred( identity, CFSTR("ocsp.sk.ee"), 0 );
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
	if( SecIdentityRef identity = SecIdentityCopyPreferred( CFSTR("ocsp.sk.ee"), 0, 0 ) )
	{
		SecKeyRef keyref = 0;
		OSStatus err = SecIdentityCopyPrivateKey( identity, &keyref );
		CFRelease( identity );
		if( !keyref )
			return QSslKey();

		CFDataRef keydata = 0;
		SecItemImportExportKeyParameters params;
		memset( &params, 0, sizeof(params) );
		params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
		params.passphrase = CFSTR("pass");
		err = SecItemExport( keyref, kSecFormatPEMSequence, 0, &params, &keydata );
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

void AccessCert::remove()
{
#ifdef Q_OS_MAC
	SecIdentityRef identity = SecIdentityCopyPreferred( CFSTR("ocsp.sk.ee"), 0, 0 );
	if( !identity )
		return;

	SecCertificateRef certref = 0;
	SecKeyRef keyref = 0;
	OSStatus err = 0;
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
	setText( msg );
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
			showWarning( tr(
				"Server access certificate expired on %1. To renew the certificate please "
				"contact IT support team of your company. Additional information is available "
				"<a href=\"mailto:sales@sk.ee\">sales@sk.ee</a> or phone 610 1892")
				.arg(c.expiryDate().toLocalTime().toString("dd.MM.yyyy")) );
			return false;
		}
		else if( c.expiryDate() < QDateTime::currentDateTime().addDays( 8 ) )
		{
			showWarning( tr(
				"Server access certificate is about to expire on %1. To renew the certificate "
				"please contact IT support team of your company. Additional information is available "
				"<a href=\"mailto:sales@sk.ee\">sales@sk.ee</a> or phone 610 1892")
				.arg(c.expiryDate().toLocalTime().toString("dd.MM.yyyy")) );
			return true;
		}
	}
	else
		remove();

	if( !c.isNull() && c.subjectInfo("CN").first() == "Sertifitseerimiskeskus AS" )
	{
		if( !c.isValid() )
		{
			showWarning( tr(
				"Update your signing software. Download and install new ID-software from "
				"<a href=\"http://www.id.ee\">www.id.ee</a>. Additional info is available "
				"<a href=\"mailto:abi@id.ee\">abi@id.ee</a> or ID-helpline 1777.") );
			return false;
		}
		QString date = "AccessCertUsage" + QDate::currentDate().toString("yyyyMM");
		if(QSettings().value(date, 0).toUInt() >= 10)
			showWarning( tr(
				"You've completed the free service limit - 10 signatures. Regarding to terms "
				"and conditions of validity confirmation service you're allowed to use the "
				"service in extent of 10 signatures per month. If you going to exceed the limit "
				"of 10 signatures per month or/and will use the service for commercial purposes, "
				"please contact to IT support team of your company or sign a contract to use the "
				"<a href=\"http://sk.ee/en/services/validity-confirmation-services\">service</a>. "
				"Additional information is available <a href=\"mailto:sales@sk.ee\">sales@sk.ee</a> "
				"or phone 610 1892") );
	}
	return true;
}
