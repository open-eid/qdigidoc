/*
 * QDigiDocCrypto
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

#include "Poller.h"

#include <common/Common.h>
#include <common/QPKCS11.h>
#include <common/TokenData.h>
#ifdef Q_OS_WIN
#include <common/QCNG.h>
#include <common/QCSP.h>
#endif

#include <libdigidoc/DigiDocConfig.h>

#include <QtCore/QEventLoop>
#include <QtCore/QFileInfo>
#include <QtCore/QHash>
#include <QtCore/QMutex>
#include <QtCore/QStringList>

class PollerPrivate
{
public:
	PollerPrivate():
#ifdef Q_OS_WIN
		cng(0),
		csp(0),
#endif
		pkcs11(0), terminate(false) {}

#ifdef Q_OS_WIN
	QCNG			*cng;
	QCSP			*csp;
#endif
	QPKCS11			*pkcs11;
	TokenData		t;
	volatile bool	terminate;
	QMutex			m;
};



Poller::Poller( ApiType api, QObject *parent )
:	QThread( parent )
,	d( new PollerPrivate )
{
	Q_INIT_RESOURCE(crypto_images);
	Q_INIT_RESOURCE(crypto_tr);
	switch( api )
	{
#ifdef Q_OS_WIN
	case CAPI: d->csp = new QCSP( this ); break;
	case CNG: d->cng = new QCNG( this ); break;
#endif
	default: d->pkcs11 = new QPKCS11( this ); break;
	}
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
		out = d->cng->decrypt( in );
		if( d->cng->lastError() == QCNG::PinCanceled )
			return PinCanceled;
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
		sleep( 2 );
#ifdef Q_OS_MAC
		QString driver = qApp->applicationDirPath() + "/" + QFileInfo( PKCS11_MODULE ).fileName();
#else
		char param[200];
		qsnprintf( param, sizeof(param), "DIGIDOC_DRIVER_%d_FILE",
			ConfigItem_lookup_int( "DIGIDOC_DEFAULT_DRIVER", 1 ) );
		QString driver = QString::fromUtf8( ConfigItem_lookup(param) );
#endif
		if( !d->pkcs11->loadDriver( driver ) )
		{
			Q_EMIT error( tr("Failed to load PKCS#11 module") + "\n" + driver );
			return;
		}
	}

	while( !d->terminate )
	{
		if( d->m.tryLock() )
		{
			TokenData old = d->t, t = old;
			QStringList cards, readers;
#ifdef Q_OS_WIN
			QCNG::Certs certs;
			if( d->csp )
			{
				cards = d->csp->containers( SslCertificate::KeyEncipherment );
				readers << "blank";
			}
			if( d->cng )
			{
				certs = d->cng->certs();
				for( QCNG::Certs::const_iterator i = certs.constBegin(); i != certs.constEnd(); ++i )
					if( i.key().keyUsage().contains( SslCertificate::KeyEncipherment ) )
						cards << i.value();
				readers << d->cng->readers();
			}
#endif
			if( d->pkcs11 )
			{
				cards = d->pkcs11->cards();
				readers = d->pkcs11->readers();
			}

			std::sort( cards.begin(), cards.end(), Common::cardsOrder );
			std::sort( readers.begin(), readers.end() );
			t.setCards( cards );
			t.setReaders( readers );

			if( !t.card().isEmpty() && !cards.contains( t.card() ) ) // check if selected card is still in slot
			{
				t.setCard( QString() );
				t.setCert( QSslCertificate() );
			}

			if( t.card().isEmpty() && !cards.isEmpty() ) // if none is selected select first from cardlist
				t.setCard( cards.first() );

			if( cards.contains( t.card() ) && t.cert().isNull() ) // read cert
			{
#ifdef Q_OS_WIN
				if( d->csp )
					t = d->csp->selectCert( t.card(), SslCertificate::KeyEncipherment );
				else if( d->cng )
				{
					for( QCNG::Certs::const_iterator i = certs.constBegin(); i != certs.constEnd(); ++i )
					{
						if( i.value() == t.card() &&
							i.key().keyUsage().contains( SslCertificate::KeyEncipherment ) )
						{
							t = d->cng->selectCert( i.key() );
							break;
						}
					}
				}
				else
#endif
					t = d->pkcs11->selectSlot( t.card(), SslCertificate::KeyEncipherment, SslCertificate::EnhancedKeyUsageNone );
				t.setCards( cards );
			}

			if( old != t ) // update data if something has changed
			{
				d->t = t;
				Q_EMIT dataChanged();
			}
			d->m.unlock();
		}

		sleep( 5 );
	}
}

void Poller::selectCard( const QString &card )
{
	TokenData t = d->t;
	t.setCard( card );
	t.setCert( QSslCertificate() );
	d->t = t;
	Q_EMIT dataChanged();
}

TokenData Poller::token() const { return d->t; }
