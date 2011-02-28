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

#include <libdigidoc/DigiDocConfig.h>

#include <QEventLoop>
#include <QMutex>
#include <QStringList>

class PollerPrivate
{
public:
	PollerPrivate(): terminate(false), refresh(false) {}

	QPKCS11			pkcs11;
	TokenData		t;
	volatile bool	terminate, refresh;
	QMutex			m;
};



Poller::Poller( QObject *parent )
:	QThread( parent )
,	d( new PollerPrivate )
{
	d->t.setCard( "loading" );
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

	switch( d->pkcs11.login( d->t ) )
	{
	case QPKCS11::PinOK: break;
	case QPKCS11::PinCanceled: return PinCanceled;
	case QPKCS11::PinIncorrect:
	{
		QEventLoop e;
		QObject::connect( this, SIGNAL(dataChanged()), &e, SLOT(quit()) );
		d->refresh = true;
		locker.unlock();
		e.exec();
		if( !(d->t.flags() & TokenData::PinLocked) )
		{
			Q_EMIT error( tr("PIN Incorrect") );
			return PinIncorrect;
		}
	}
	case QPKCS11::PinLocked:
		Q_EMIT error( tr("PIN Locked") );
		return PinLocked;
	default:
		Q_EMIT error( tr("Failed to login token") );
		return DecryptFailed;
	}

	char *data = new char[in.size()];
	unsigned long size = 0;
	bool status = d->pkcs11.decrypt( in, (unsigned char*)data, &size );
	d->pkcs11.logout();
	if( !status )
		Q_EMIT error( tr("Failed to decrypt document") );
	else
		out = QByteArray( data, size );
	delete [] data;
	return status ? DecryptOK : DecryptFailed;
}

void Poller::run()
{
	d->terminate = false;
	d->t.clear();
	d->t.setCard( "loading" );

	char driver[200];
	qsnprintf( driver, sizeof(driver), "DIGIDOC_DRIVER_%d_FILE",
		ConfigItem_lookup_int( "DIGIDOC_DEFAULT_DRIVER", 1 ) );
	if( !d->pkcs11.loadDriver( QString::fromUtf8( ConfigItem_lookup(driver) ) ) )
	{
		Q_EMIT error( tr("Failed to load PKCS#11 module") );
		return;
	}

	while( !d->terminate )
	{
		if( d->m.tryLock() )
		{
			QStringList cards = d->pkcs11.cards();
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

			if( cards.contains( d->t.card() ) && (d->t.cert().isNull() || d->refresh) ) // read cert
			{
				d->t = d->pkcs11.selectSlot( d->t.card(), SslCertificate::DataEncipherment );
				d->t.setCards( cards );
				d->refresh = false;
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
