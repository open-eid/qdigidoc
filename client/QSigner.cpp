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

#include "QSigner.h"

#include "Application.h"

#ifdef Q_OS_WIN
#include <common/QCSP.h>
#include <common/QCNG.h>
#else
class QCSP;
class QCNG;
#endif
#include <common/QPKCS11.h>
#include <common/TokenData.h>

#include <digidocpp/crypto/X509Cert.h>

#include <QtCore/QEventLoop>
#include <QtCore/QMutex>
#include <QtCore/QStringList>
#include <QtNetwork/QSslKey>

#include <openssl/obj_mac.h>

class QSignerPrivate
{
public:
	QSignerPrivate(): csp(0), cng(0), pkcs11(0), terminate(false) {}

	QCSP			*csp;
	QCNG			*cng;
	QPKCS11			*pkcs11;
	TokenData		auth, sign;
	volatile bool	terminate;
	QMutex			m;
};

using namespace digidoc;

QSigner::QSigner( ApiType api, QObject *parent )
:	QThread( parent )
,	d( new QSignerPrivate )
{
	switch( api )
	{
#ifdef Q_OS_WIN
	case CAPI: d->csp = new QCSP( this ); break;
	case CNG: d->cng = new QCNG( this ); break;
#endif
	default: d->pkcs11 = new QPKCS11( this ); break;
	}
	d->auth.setCard( "loading" );
	d->sign.setCard( "loading" );
	connect( this, SIGNAL(error(QString)), SLOT(showWarning(QString)) );
	start();
}

QSigner::~QSigner()
{
	d->terminate = true;
	wait();
	delete d;
}

QSigner::ApiType QSigner::apiType() const
{
	if( d->csp ) return CAPI;
	if( d->cng ) return CNG;
	return PKCS11;
}

X509Cert QSigner::cert() const
{
	if( d->sign.cert().isNull() )
		throw Exception( __FILE__, __LINE__, QSigner::tr("Sign certificate is not selected").toUtf8().constData() );
	try
	{
		QByteArray der = d->sign.cert().toDer();
		return X509Cert(std::vector<unsigned char>(der.constData(), der.constData() + der.size()));
	}
	catch(const Exception &e)
	{
		throw Exception( __FILE__, __LINE__, QSigner::tr("Sign certificate is not selected").toUtf8().constData(), e );
	}

	return X509Cert();
}

QSigner::ErrorCode QSigner::decrypt( const QByteArray &in, QByteArray &out )
{
	QMutexLocker locker( &d->m );
	if( !d->auth.cards().contains( d->auth.card() ) || d->auth.cert().isNull() )
	{
		Q_EMIT error( tr("Authentication certificate is not selected.") );
		return DecryptFailed;
	}

	if( d->pkcs11 )
	{
		QPKCS11::PinStatus status = d->pkcs11->login( d->auth );
		switch( status )
		{
		case QPKCS11::PinOK: break;
		case QPKCS11::PinCanceled: return PinCanceled;
		case QPKCS11::PinIncorrect:
			locker.unlock();
			reloadauth();
			if( !(d->auth.flags() & TokenData::PinLocked) )
			{
				Q_EMIT error( QPKCS11::errorString( status ) );
				return PinIncorrect;
			}
			// else pin locked, fall through
		case QPKCS11::PinLocked:
			Q_EMIT error( QPKCS11::errorString( status ) );
			return PinLocked;
		default:
			Q_EMIT error( tr("Failed to login token") + " " + QPKCS11::errorString( status ) );
			return DecryptFailed;
		}
		out = d->pkcs11->decrypt( in );
		d->pkcs11->logout();
	}
#ifdef Q_OS_WIN
	else if( d->csp )
	{
		out = d->csp->decrypt( in );
		if( d->csp->lastError() == QCSP::PinCanceled )
			return PinCanceled;
	}
	else if( d->cng )
	{
		d->cng->selectCert( d->auth.cert() );
		out = d->cng->decrypt( in );
		if( d->cng->lastError() == QCNG::PinCanceled )
			return PinCanceled;
	}
#endif

	if( out.isEmpty() )
		Q_EMIT error( tr("Failed to decrypt document") );
	locker.unlock();
	reloadauth();
	return !out.isEmpty() ? DecryptOK : DecryptFailed;
}

Qt::HANDLE QSigner::handle() const
{
	if( d->csp ) return Qt::HANDLE(d->csp);
	if( d->cng ) return Qt::HANDLE(d->cng);
	return Qt::HANDLE(d->pkcs11);
}

void QSigner::lock() { d->m.lock(); }

void QSigner::reloadauth()
{
	QEventLoop e;
	QObject::connect( this, SIGNAL(authDataChanged()), &e, SLOT(quit()) );
	d->m.lock();
	d->auth.setCert( QSslCertificate() );
	d->m.unlock();
	e.exec();
}

void QSigner::reloadsign()
{
	QEventLoop e;
	QObject::connect( this, SIGNAL(signDataChanged()), &e, SLOT(quit()) );
	d->m.lock();
	d->sign.setCert( QSslCertificate() );
	d->m.unlock();
	e.exec();
}

void QSigner::run()
{
	d->terminate = false;
	d->auth.clear();
	d->auth.setCard( "loading" );
	d->sign.clear();
	d->sign.setCard( "loading" );

	QString driver = qApp->confValue( Application::PKCS11Module ).toString();
	if( d->pkcs11 && !d->pkcs11->loadDriver( driver ) )
	{
		Q_EMIT error( tr("Failed to load PKCS#11 module") + "\n" + driver );
		return;
	}

	while( !d->terminate )
	{
		if( d->m.tryLock() )
		{
			TokenData aold = d->auth, at = aold;
			TokenData sold = d->sign, st = sold;
			QStringList acards, scards, readers;
#ifdef Q_OS_WIN
			QCNG::Certs certs;
			if( d->csp )
			{
				acards = d->csp->containers( SslCertificate::KeyEncipherment );
				scards = d->csp->containers( SslCertificate::NonRepudiation );
				readers << "blank";
			}
			if( d->cng )
			{
				certs = d->cng->certs();
				for( QCNG::Certs::const_iterator i = certs.constBegin(); i != certs.constEnd(); ++i )
				{
					if( i.key().keyUsage().contains( SslCertificate::KeyEncipherment ) )
						acards << i.value();
					if( i.key().keyUsage().contains( SslCertificate::NonRepudiation ) )
						scards << i.value();
				}
				readers << d->cng->readers();
			}
#endif
			QList<TokenData> pkcs11;
			if( d->pkcs11 )
			{
				pkcs11 = d->pkcs11->tokens();
				Q_FOREACH( const TokenData &t, pkcs11 )
				{
					SslCertificate c( t.cert() );
					if( c.keyUsage().contains( SslCertificate::KeyEncipherment ) )
						acards << t.card();
					if( c.keyUsage().contains( SslCertificate::NonRepudiation ) )
						scards << t.card();
				}
				acards.removeDuplicates();
				scards.removeDuplicates();
				readers = d->pkcs11->readers();
			}

			std::sort( acards.begin(), acards.end(), Common::cardsOrder );
			std::sort( scards.begin(), scards.end(), Common::cardsOrder );
			std::sort( readers.begin(), readers.end() );
			at.setCards( acards );
			at.setReaders( readers );
			st.setCards( scards );
			st.setReaders( readers );

			if( !at.card().isEmpty() && !acards.contains( at.card() ) ) // check if selected auth card is still in slot
			{
				at.setCard( QString() );
				at.setCert( QSslCertificate() );
			}
			if( !st.card().isEmpty() && !scards.contains( st.card() ) ) // check if selected sign card is still in slot
			{
				st.setCard( QString() );
				st.setCert( QSslCertificate() );
			}

			if( at.card().isEmpty() && !acards.isEmpty() ) // if none is selected select first auth from cardlist
				at.setCard( acards.first() );
			if( st.card().isEmpty() && !scards.isEmpty() ) // if none is selected select first sign from cardlist
				st.setCard( scards.first() );

			if( acards.contains( at.card() ) && at.cert().isNull() ) // read auth cert
			{
#ifdef Q_OS_WIN
				if( d->csp )
					at = d->csp->selectCert( at.card(), SslCertificate::KeyEncipherment );
				else if( d->cng )
				{
					for( QCNG::Certs::const_iterator i = certs.constBegin(); i != certs.constEnd(); ++i )
					{
						if( i.value() == at.card() &&
							i.key().keyUsage().contains( SslCertificate::KeyEncipherment ) )
						{
							at.setCert( i.key() );
							break;
						}
					}
				}
				else
#endif
				{
					Q_FOREACH( const TokenData &i, pkcs11 )
					{
						if( i.card() == at.card() && SslCertificate( i.cert() ).keyUsage().contains( SslCertificate::KeyEncipherment ) )
						{
							at.setCert( i.cert() );
							at.setFlags( i.flags() );
							break;
						}
					}
				}
			}

			if( scards.contains( st.card() ) && st.cert().isNull() ) // read sign cert
			{
#ifdef Q_OS_WIN
				if( d->csp )
					st = d->csp->selectCert( st.card(), SslCertificate::NonRepudiation );
				else if( d->cng )
				{
					for( QCNG::Certs::const_iterator i = certs.constBegin(); i != certs.constEnd(); ++i )
					{
						if( i.value() == st.card() &&
							i.key().keyUsage().contains( SslCertificate::NonRepudiation ) )
						{
							st.setCert( i.key() );
							break;
						}
					}
				}
				else
#endif
				{
					Q_FOREACH( const TokenData &i, pkcs11 )
					{
						if( i.card() == st.card() && SslCertificate( i.cert() ).keyUsage().contains( SslCertificate::NonRepudiation ) )
						{
							st.setCert( i.cert() );
							st.setFlags( i.flags() );
							break;
						}
					}
				}
			}

			if( aold != at ) // update auth data if something has changed
			{
				d->auth = at;
				Q_EMIT authDataChanged();
			}
			if( sold != st ) // update sign data if something has changed
			{
				d->sign = st;
				Q_EMIT signDataChanged();
			}
			d->m.unlock();
		}

		sleep( 5 );
	}
}

void QSigner::selectAuthCard( const QString &card )
{
	TokenData t = d->auth;
	t.setCard( card );
	t.setCert( QSslCertificate() );
	d->auth = t;
	Q_EMIT signDataChanged();
}

void QSigner::selectSignCard( const QString &card )
{
	TokenData t = d->sign;
	t.setCard( card );
	t.setCert( QSslCertificate() );
	d->sign = t;
	Q_EMIT signDataChanged();
}

void QSigner::showWarning( const QString &msg )
{ qApp->showWarning( msg ); }

void QSigner::sign(const std::string &method, const std::vector<unsigned char> &digest,
	std::vector<unsigned char> &signature )
{
	QMutexLocker locker( &d->m );
	if( !d->sign.cards().contains( d->sign.card() ) || d->sign.cert().isNull() )
		throwException( tr("Signing certificate is not selected."), Exception::General, __LINE__ );

	int type = NID_sha1;
	if( method == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224" ) type = NID_sha224;
	if( method == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" ) type = NID_sha256;
	if( method == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" ) type = NID_sha384;
	if( method == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" ) type = NID_sha512;

	QByteArray sig;
	if( d->pkcs11 )
	{
		QPKCS11::PinStatus status = d->pkcs11->login( d->sign );
		switch( status )
		{
		case QPKCS11::PinOK: break;
		case QPKCS11::PinCanceled:
			throwException( tr("Failed to login token") + " " + QPKCS11::errorString( status ), Exception::PINCanceled, __LINE__ );
		case QPKCS11::PinIncorrect:
			throwException( tr("Failed to login token") + " " + QPKCS11::errorString( status ), Exception::PINIncorrect, __LINE__ );
		case QPKCS11::PinLocked:
			locker.unlock();
			reloadsign();
			throwException( tr("Failed to login token") + " " + QPKCS11::errorString( status ), Exception::PINLocked, __LINE__ );
		default:
			throwException( tr("Failed to login token") + " " + QPKCS11::errorString( status ), Exception::General, __LINE__ );
		}

		sig = d->pkcs11->sign( type, QByteArray( (const char*)&digest[0], digest.size() ) );
		d->pkcs11->logout();
	}
#ifdef Q_OS_WIN
	else if( d->csp )
	{
		sig = d->csp->sign( type, QByteArray( (const char*)&digest[0], digest.size() ) );
		if( d->csp->lastError() == QCSP::PinCanceled )
			throwException( tr("Failed to login token"), Exception::PINCanceled, __LINE__ );
	}
	else if( d->cng )
	{
		d->cng->selectCert( d->sign.cert() );
		sig = d->cng->sign( type, QByteArray( (const char*)&digest[0], digest.size() ) );
		if( d->cng->lastError() == QCNG::PinCanceled )
			throwException( tr("Failed to login token"), Exception::PINCanceled, __LINE__ );
	}
#endif

	locker.unlock();
	reloadsign();
	if( sig.isEmpty() )
		throwException( tr("Failed to sign document"), Exception::General, __LINE__ );
	signature.resize( sig.size() );
	std::memcpy( &signature[0], sig.constData(), sig.size() );
}

void QSigner::throwException( const QString &msg, Exception::ExceptionCode code, int line )
{
	QString t = msg;
	Exception e( __FILE__, line, t.toUtf8().constData() );
	e.setCode( code );
	throw e;
}

TokenData QSigner::tokenauth() const { return d->auth; }
TokenData QSigner::tokensign() const { return d->sign; }

void QSigner::unlock() { d->m.unlock(); reloadsign(); }
