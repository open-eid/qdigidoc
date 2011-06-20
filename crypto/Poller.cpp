/*
 * QDigiDocCrypto
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

#include "Poller.h"

#include <common/QPKCS11.h>
#include <common/TokenData.h>
#ifdef Q_OS_WIN
#include <common/QCSP.h>
#endif

#include <libdigidoc/DigiDocConfig.h>

#include <QEventLoop>
#include <QMutex>
#include <QStringList>

class PollerPrivate
{
public:
	PollerPrivate():
#ifdef Q_OS_WIN
		csp(0),
#endif
		pkcs11(0), terminate(false) {}

#ifdef Q_OS_WIN
	QCSP			*csp;
#endif
	QPKCS11			*pkcs11;
	TokenData		t;
	volatile bool	terminate;
	QMutex			m;
};



Poller::Poller( bool useCapi, QObject *parent )
:	QThread( parent )
,	d( new PollerPrivate )
{
#ifdef Q_OS_WIN
	if( useCapi )
		d->csp = new QCSP( this );
	else
#else
	Q_UNUSED(useCapi)
#endif
		d->pkcs11 = new QPKCS11( this );
	d->t.setCard( "loading" );
	connect( this, SIGNAL(error(QString)), qApp, SLOT(showWarning(QString)) );
	start();
}

Poller::~Poller()
{
	d->terminate = true;
	wait();
	delete d;
}

Poller::ErrorCode Poller::decrypt( const QByteArray &in, QByteArray &out )
{
	QMutexLocker locker( &d->m );
	if( !d->t.cards().contains( d->t.card() ) || d->t.cert().isNull() )
	{
		Q_EMIT error( tr("Authentication certificate is not selected.") );
		return DecryptFailed;
	}

	if( d->pkcs11 )
	{
		QPKCS11::PinStatus status = d->pkcs11->login( d->t );
		switch( status )
		{
		case QPKCS11::PinOK: break;
		case QPKCS11::PinCanceled: return PinCanceled;
		case QPKCS11::PinIncorrect:
			locker.unlock();
			reload();
			if( !(d->t.flags() & TokenData::PinLocked) )
			{
				Q_EMIT error( QPKCS11::errorString( status ) );
				return PinIncorrect;
			}
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
	}
#endif

	if( out.isEmpty() )
		Q_EMIT error( tr("Failed to decrypt document") );
	locker.unlock();
	reload();
	return !out.isEmpty() ? DecryptOK : DecryptFailed;
}

void Poller::reload()
{
	QEventLoop e;
	QObject::connect( this, SIGNAL(dataChanged()), &e, SLOT(quit()) );
	d->m.lock();
	d->t.setCert( QSslCertificate() );
	d->m.unlock();
	e.exec();
}

void Poller::run()
{
	d->terminate = false;
	d->t.clear();
	d->t.setCard( "loading" );

	if( d->pkcs11 )
	{
		char driver[200];
		qsnprintf( driver, sizeof(driver), "DIGIDOC_DRIVER_%d_FILE",
			ConfigItem_lookup_int( "DIGIDOC_DEFAULT_DRIVER", 1 ) );
		if( !d->pkcs11->loadDriver( QString::fromUtf8( ConfigItem_lookup(driver) ) ) )
		{
			Q_EMIT error( tr("Failed to load PKCS#11 module") );
			return;
		}
	}

	while( !d->terminate )
	{
		if( d->m.tryLock() )
		{
			QStringList cards;
#ifdef Q_OS_WIN
			if( d->csp )
				cards = d->csp->containers( SslCertificate::DataEncipherment );
#endif
			if( d->pkcs11 )
				cards = d->pkcs11->cards();
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
				if( d->csp )
					d->t = d->csp->selectCert( d->t.card(), SslCertificate::DataEncipherment );
				else
#endif
					d->t = d->pkcs11->selectSlot( d->t.card(), SslCertificate::DataEncipherment );
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

void Poller::selectCard( const QString &card )
{
	d->t.setCard( card );
	d->t.setCert( QSslCertificate() );
	Q_EMIT dataChanged();
}

TokenData Poller::token() const { return d->t; }
