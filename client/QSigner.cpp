/*
 * QDigiDocClient
 *
 * Copyright (C) 2009-2011 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009-2011 Raul Metsma <raul@innovaatik.ee>
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
#endif
#include <common/QPKCS11.h>
#include <common/TokenData.h>

#include <digidocpp/Conf.h>

#include <QEventLoop>
#include <QMutex>
#include <QSslKey>
#include <QStringList>

class QSignerPrivate
{
public:
	QSignerPrivate(): terminate(false) {}

	QPKCS11			pkcs11;
	TokenData		t;
	volatile bool	terminate;
	QMutex			m;
	QStringList		providers;
#ifdef Q_OS_WIN
	QCSP		csp;
#endif
};

using namespace digidoc;

QSigner::QSigner( QObject *parent )
:	QThread( parent )
,	d( new QSignerPrivate )
{
	d->t.setCard( "loading" );
	connect( this, SIGNAL(error(QString)), SLOT(showWarning(QString)) );
}

QSigner::~QSigner()
{
	d->terminate = true;
	wait();
	delete d;
}

X509* QSigner::getCert() throw(digidoc::SignException)
{
	if( d->t.cert().isNull() )
		throw SignException( __FILE__, __LINE__, tr("Sign certificate is not selected").toUtf8().constData() );
	return (X509*)d->t.cert().handle();
}

QPKCS11* QSigner::handle() const { return &d->pkcs11; }

void QSigner::lock() { d->m.lock(); }

void QSigner::reload()
{
	QEventLoop e;
	QObject::connect( this, SIGNAL(dataChanged()), &e, SLOT(quit()) );
	d->m.lock();
	d->t.setCert( QSslCertificate() );
	d->m.unlock();
	e.exec();
}

void QSigner::run()
{
	d->terminate = false;
	d->t.clear();
	d->t.setCard( "loading" );

	bool loaded = false;
	try
	{
		loaded = d->pkcs11.loadDriver( QString::fromUtf8(
			Conf::getInstance()->getPKCS11DriverPath().c_str() ) );
	}
	catch( const Exception & ) {}

	if( !loaded )
	{
		Q_EMIT error( tr("Failed to load PKCS#11 module") );
		return;
	}

	while( !d->terminate )
	{
		if( d->m.tryLock() )
		{
#ifdef Q_OS_WIN
			d->providers = d->csp.containers();
#endif
			QStringList cards = d->pkcs11.cards() +  d->providers;
			bool update = d->t.cards() != cards; // check if cards have inserted/removed, update list
			d->t.setCards( cards );

			if( !d->t.card().isEmpty() && !cards.contains( d->t.card() ) ) // check if selected card is still in slot
			{
				d->t.setCard( QString() );
				d->t.setCert( QSslCertificate() );
				update = true;
			}

			if( d->t.card().isEmpty() && !cards.isEmpty() ) // if none is selected select first from cardlist
				selectCard( cards.first() );

			if( cards.contains( d->t.card() ) && d->t.cert().isNull() ) // read cert
			{
#ifdef Q_OS_WIN
				if( d->providers.contains( d->t.card() ) )
					d->t = d->csp.selectCert( d->t.card(), SslCertificate::NonRepudiation );
				else
#endif
					d->t = d->pkcs11.selectSlot( d->t.card(), SslCertificate::NonRepudiation );
				d->t.setCards( cards );
				update = true;
			}

			if( update ) // update data if something has changed
				Q_EMIT dataChanged();
			d->m.unlock();
		}

		sleep( 5 );
	}
}

void QSigner::selectCard( const QString &card )
{
	d->t.setCard( card );
	d->t.setCert( QSslCertificate() );
	Q_EMIT dataChanged();
}

int QSigner::type()
{
	switch( SslCertificate(d->t.cert()).type() )
	{
	case SslCertificate::DigiIDType:
	case SslCertificate::DigiIDTestType:
		return NID_sha256;
	default: break;
	}
	return d->t.cert().publicKey().length() > 1024 ? NID_sha256 : NID_sha224;
}

void QSigner::showWarning( const QString &msg )
{ qApp->showWarning( msg ); }

void QSigner::sign( const Digest &digest, Signature &signature ) throw(digidoc::SignException)
{
	QMutexLocker locker( &d->m );
	if( !d->t.cards().contains( d->t.card() ) || d->t.cert().isNull() )
		throwException( tr("Signing certificate is not selected."), Exception::NoException, __LINE__ );

	QByteArray sig;
	if( !d->providers.contains( d->t.card() ) )
	{
		switch( d->pkcs11.login( d->t ) )
		{
		case QPKCS11::PinOK: break;
		case QPKCS11::PinCanceled:
			throwException( tr("Failed to login token"), Exception::PINCanceled, __LINE__ );
		case QPKCS11::PinIncorrect:
			locker.unlock();
			reload();
			throwException( tr("Failed to login token"), Exception::PINIncorrect, __LINE__ );
		case QPKCS11::PinLocked:
			throwException( tr("Failed to login token"), Exception::PINLocked, __LINE__ );
		default:
			throwException( tr("Failed to login token"), Exception::NoException, __LINE__ );
		}

		sig = d->pkcs11.sign( digest.type, QByteArray( (const char*)digest.digest, digest.length ) );
		d->pkcs11.logout();
	}
#ifdef Q_OS_WIN
	else
	{
		/*switch( d->csp.login( d->t ) )
		{
		case QCSP::PinOK: break;
		case QCSP::PinCanceled:
			throwException( tr("Failed to login token"), Exception::PINCanceled, __LINE__ );
		default:
			throwException( tr("Failed to login token"), Exception::NoException, __LINE__ );
		}*/
		sig = d->csp.sign( digest.type, QByteArray( (const char*)digest.digest, digest.length ) );
	}
#endif

	locker.unlock();
	reload();
	if( sig.isEmpty() )
		throwException( tr("Failed to sign document"), Exception::NoException, __LINE__ );
	signature.length = sig.size();
	signature.signature = (unsigned char*)qMalloc( sig.size() );
	qMemCopy( signature.signature, sig.constData(), sig.size() );
}

void QSigner::throwException( const QString &msg, Exception::ExceptionCode code, int line ) throw(SignException)
{
	QString t = msg;
	SignException e( __FILE__, line, t.toUtf8().constData() );
	e.setCode( code );
	throw e;
}

TokenData QSigner::token() const { return d->t; }

void QSigner::unlock() { d->m.unlock(); reload(); }
