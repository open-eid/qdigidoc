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

#include "QCSP.h"

#include <common/PinDialog.h>

#include <QtCore/QDebug>
#include <QtWidgets/QApplication.h>

#include <qt_windows.h>
#include <WinCrypt.h>

#include <openssl/obj_mac.h>

class QCSPPrivate
{
public:
	QCSPPrivate(): h(0), error(QCSP::PinOK) {}

	static QByteArray provParam( HCRYPTPROV h, DWORD param, DWORD flags = 0 );
	static QByteArray keyParam( HCRYPTKEY key, DWORD param, DWORD flags = 0 );

	HCRYPTPROV h;
	QHash<QString,QPair<QString,QString> > certs;
	QCSP::PinStatus error;
};



QByteArray QCSPPrivate::keyParam( HCRYPTKEY key, DWORD param, DWORD flags )
{
	DWORD size = 0;
	if( !CryptGetKeyParam( key, param, 0, &size, flags ) )
		return QByteArray();
	QByteArray data( size, 0 );
	if( !CryptGetKeyParam( key, param, LPBYTE(data.data()), &size, flags ) )
		return QByteArray();
	return data;
}

QByteArray QCSPPrivate::provParam( HCRYPTPROV h, DWORD param, DWORD flags )
{
	DWORD size = 0;
	if( !CryptGetProvParam( h, param, 0, &size, flags ) )
		return QByteArray();
	QByteArray data( size, 0 );
	if( !CryptGetProvParam( h, param, LPBYTE(data.data()), &size, flags ) )
		return QByteArray();
	return data;
}



QCSP::QCSP( QObject *parent )
:	QObject( parent )
,	d( new QCSPPrivate )
{
}

QCSP::~QCSP()
{
	if( d->h )
		CryptReleaseContext( d->h, 0 );
	delete d;
}

QByteArray QCSP::decrypt( const QByteArray &data )
{
	HCRYPTKEY key = 0;
	if( !CryptGetUserKey( d->h, AT_KEYEXCHANGE, &key ) )
		return QByteArray();

	QByteArray rev = reverse( data );
	DWORD size = rev.size();
	bool result = CryptDecrypt( key, 0, true, 0, LPBYTE(rev.data()), &size );
	CryptDestroyKey( key );

	return result ? rev : QByteArray();
}

QCSP::PinStatus QCSP::lastError() const { return d->error; }

QCSP::PinStatus QCSP::login( const TokenData &t )
{
	if( !d->h )
		return PinUnknown;

	PinDialog dialog( PinDialog::Pin2Type, t, qApp->activeWindow() );
	if( !dialog.exec() )
		return PinCanceled;
	return CryptSetProvParam( d->h, PP_SIGNATURE_PIN, LPBYTE(dialog.text().utf16()), 0 ) ? PinOK : PinUnknown;
}

QStringList QCSP::containers( SslCertificate::KeyUsage usage )
{
	qWarning() << "Start enumerationg providers";
	QHash<QString,QPair<QString,QString> > certs;
	HCRYPTPROV h = 0;
	DWORD index = 0, type = 0, size = 0;
	while( CryptEnumProvidersW( index, 0, 0, &type, 0, &size ) )
	{
		QString provider( size / sizeof(wchar_t) - 1, 0 );
		if( !CryptEnumProvidersW( index++, 0, 0, &type, LPWSTR(provider.data()), &size ) )
			continue;

		qWarning() << "Found provider" << provider << "type" << type;
		if( type != PROV_RSA_FULL )
			continue;

		// its broken and does not play well with pkcs11
		if( provider.toLower().contains( "esteid" ) )
			continue;

		qWarning() << "Acquiring provider" << provider << "context";
		if( h )
			CryptReleaseContext( h, 0 );
		h = 0;
		if( !CryptAcquireContextW( &h, 0, LPCWSTR(provider.utf16()), type, CRYPT_SILENT ) )
			continue;

		qWarning() << "Checking if provider" << provider << "is HW";
		QByteArray imptype = QCSPPrivate::provParam( h, PP_IMPTYPE );
		if( imptype.isEmpty() || !(imptype[0] & CRYPT_IMPL_HARDWARE) )
			continue;

		qWarning() << "Enumerating provider " << provider << "containers";
		QStringList containers;
		QByteArray container = QCSPPrivate::provParam( h, PP_ENUMCONTAINERS, CRYPT_FIRST );
		while( !container.isEmpty() )
		{
			containers << container;
			container = QCSPPrivate::provParam( h, PP_ENUMCONTAINERS, CRYPT_NEXT );
		}
		qWarning() << "Provider" << provider << "containers" << containers;

		Q_FOREACH( const QString &container, containers )
		{
			if( h )
				CryptReleaseContext( h, 0 );
			h = 0;
			qWarning() << "Acquiring provider" << provider << "container" << container << "context";
			if( !CryptAcquireContextW( &h, LPCWSTR(container.utf16()), LPCWSTR(provider.utf16()), type, CRYPT_SILENT ) )
				continue;

			qWarning() << "Geting provider" << provider << "container" << container << "key";
			HCRYPTKEY key = 0;
			if( !CryptGetUserKey( h, usage == SslCertificate::NonRepudiation ? AT_SIGNATURE : AT_KEYEXCHANGE, &key ) )
				continue;

			qWarning() << "Reading provider" << provider << "container" << container << "cert";
			SslCertificate cert( QCSPPrivate::keyParam( key, KP_CERTIFICATE, 0 ), QSsl::Der );
			CryptDestroyKey( key );

			if( cert.isNull() )
				continue;

			qWarning() << "Adding provider" << provider << "container" << container << "list";
			certs.insert( cert.subjectInfo( QSslCertificate::CommonName ), QPair<QString,QString>( provider, container ) );
		}
	}
	if( h )
		CryptReleaseContext( h, 0 );
	qWarning() << "End enumerationg providers";

	d->certs = certs;
	return d->certs.keys();
}

QByteArray QCSP::reverse( const QByteArray &data ) const
{
	QByteArray reverse;
	for( QByteArray::const_iterator i = data.constEnd(); i != data.constBegin(); )
	{
		--i;
		reverse += *i;
	}
	return reverse;
}

TokenData QCSP::selectCert( const QString &cn, SslCertificate::KeyUsage usage )
{
	TokenData t;
	t.setCard( cn );

	if( d->h )
		CryptReleaseContext( d->h, 0 );

	QPair<QString,QString> c = d->certs.value( cn );
	if( !CryptAcquireContextW( &d->h, LPCWSTR(c.second.utf16()), LPCWSTR(c.first.utf16()), PROV_RSA_FULL, 0 ) )
		return t;

	HCRYPTKEY key = 0;
	if( !CryptGetUserKey( d->h, usage == SslCertificate::NonRepudiation ? AT_SIGNATURE : AT_KEYEXCHANGE, &key ) )
		return t;

	SslCertificate cert = QSslCertificate( d->keyParam( key, KP_CERTIFICATE, 0 ), QSsl::Der );
	CryptDestroyKey( key );
	if( cert.keyUsage().keys().contains( usage ) )
		t.setCert( cert );

	return t;
}

QByteArray QCSP::sign( int method, const QByteArray &digest )
{
	ALG_ID alg = 0;
	switch( method )
	{
	case NID_sha1: alg = CALG_SHA1; break;
	case NID_sha256: alg = CALG_SHA_256; break;
	case NID_sha384: alg = CALG_SHA_384; break;
	case NID_sha512: alg = CALG_SHA_512; break;
	case NID_sha224:
	default: return QByteArray();
	}

	HCRYPTHASH hash = 0;
	if( !CryptCreateHash( d->h, alg, 0, 0, &hash ) )
		return QByteArray();

	if( !CryptSetHashParam( hash, HP_HASHVAL, LPBYTE(digest.constData()), 0 ) )
	{
		CryptDestroyHash( hash );
		return QByteArray();
	}

	DWORD size = 256;
	QByteArray sig( size, 0 );
	if( CryptSignHashW( hash, AT_SIGNATURE, 0, 0, LPBYTE(sig.data()), &size ) )
		sig.resize( size );
	else
		sig.clear();
	switch( GetLastError() )
	{
	case ERROR_CANCELLED: d->error = PinCanceled; break;
	default: break;
	}

	CryptDestroyHash( hash );
	return reverse( sig );
}
