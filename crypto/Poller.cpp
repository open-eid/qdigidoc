/*
 * QDigiDocCrypto
 *
 * Copyright (C) 2009,2010 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009,2010 Raul Metsma <raul@innovaatik.ee>
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

#include <QMutex>
#include <QStringList>

class PollerPrivate
{
public:
	PollerPrivate(): code(Poller::NullCode), terminate(false) {}

	Poller::ErrorCode code;
	QPKCS11			pkcs11;
	TokenData		t;
	volatile bool	terminate;
	QMutex			m;
	QString			select;
};



Poller::Poller( QObject *parent )
:	QThread( parent )
,	d( new PollerPrivate )
{}

Poller::~Poller()
{
	d->terminate = true;
	wait();
	delete d;
}

bool Poller::decrypt( const QByteArray &in, QByteArray &out )
{
	QMutexLocker locker( &d->m );
	if( !d->t.cards().contains( d->t.card() ) || d->t.cert().isNull() )
	{
		emitError( tr("Authentication certificate is not selected.") );
		return false;
	}

	switch( d->pkcs11.login( d->t ) )
	{
	case QPKCS11::PinOK: break;
	case QPKCS11::PinCanceled:
		emitError( tr("PIN acquisition canceled."), PinCanceled );
		return false;
	case QPKCS11::PinIncorrect:
		emitError( tr("PIN Incorrect"), PinIncorrect );
		return false;
	case QPKCS11::PinLocked:
		emitError( tr("PIN Locked"), PinLocked );
		return false;
	default:
		emitError( tr("Failed to login token") );
		return false;
	}

	char *data = new char[in.size()];
	unsigned long size = 0;
	bool status = d->pkcs11.decrypt( in, (unsigned char*)data, &size );
	d->pkcs11.logout();
	if( !status )
		emitError( tr("Failed to decrypt document") );
	else
		out = QByteArray( data, size );
	delete [] data;
	return status;
}

void Poller::emitError( const QString &msg, ErrorCode code )
{ Q_EMIT error( msg, quint8(d->code = code) ); }

Poller::ErrorCode Poller::errorCode() const { return d->code; }

void Poller::run()
{
	d->terminate = false;
	d->t.clear();

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
			bool update = false;
			if( (update = d->t.cards() != cards) ) // check if cards have inserted/removed, update list
				d->t.setCards( cards );

			if( !d->t.card().isEmpty() && !cards.contains( d->t.card() ) ) // check if selected card is still in slot
			{
				d->t.setCert( QSslCertificate() );
				d->t.setCard( QString() );
				d->t.setFlags( 0 );
				update = true;
			}

			if( !d->select.isEmpty() && cards.contains( d->select ) ) // select forced selection slot
			{
				selectCert( d->select );
				d->select.clear();
				update = true;
			}
			else if( d->t.card().isEmpty() && !cards.isEmpty() ) // if none is selected select first from cardlist
			{
				selectCert( cards.first() );
				update = true;
			}
			if( update ) // update data if something has changed
				Q_EMIT dataChanged( d->t );
			d->m.unlock();
		}

		sleep( 5 );
	}
}

void Poller::selectCard( const QString &card ) { d->select = card; }

void Poller::selectCert( const QString &card )
{
	TokenData t = d->pkcs11.selectSlot( card, SslCertificate::DataEncipherment );
	t.setCards( d->t.cards() );
	d->t = t;
}
