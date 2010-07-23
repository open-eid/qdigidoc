/*
 * QDigiDocCrypto
 *
 * Copyright (C) 2009 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009 Raul Metsma <raul@innovaatik.ee>
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

#include "common/PinDialog.h"
#include "common/SslCertificate.h"

#include <libdigidoc/DigiDocConfig.h>
#include <libp11.h>

#include <QApplication>
#include <QMutex>
#include <QStringList>

#define CKM_RSA_PKCS			(0x00000001)

#define CKR_OK					(0)
#define CKR_CANCEL				(1)
#define CKR_FUNCTION_CANCELED	(0x50)
#define CKR_PIN_INCORRECT		(0xa0)
#define CKR_PIN_LOCKED			(0xa4)

class PollerPrivate
{
public:
	PollerPrivate()
	: code( Poller::NullCode )
	, login(false)
	, terminate(false)
	, handle(0)
	, slot(0)
	, slotCount(0)
	, loginResult(CKR_OK)
	{}

	Poller::ErrorCode code;
	volatile bool	login, terminate;
	QMutex			m;
	QHash<QString,unsigned int> cards;
	QString			selectedCard, select;
	QSslCertificate	sign;
	PKCS11_CTX		*handle;
	PKCS11_SLOT     *slot, *slots;
	unsigned int	slotCount;
	unsigned long	loginResult;
};



Poller::Poller( QObject *parent )
:	QThread( parent )
,	d( new PollerPrivate )
{}

Poller::~Poller() { unloadDriver(); delete d; }

bool Poller::decrypt( const QByteArray &in, QByteArray &out )
{
	QMutexLocker locker(&d->m);
	if( !d->cards.contains( d->selectedCard ) || d->sign.isNull() )
	{
		emitError( tr("Authentication certificate is not selected."), 0 );
		return false;
	}

	if( d->slotCount )
	{
		PKCS11_release_all_slots( d->handle, d->slots, d->slotCount );
		d->slotCount = 0;
	}
	if( PKCS11_enumerate_slots( d->handle, &d->slots, &d->slotCount ) ||
		d->cards[d->selectedCard] >= d->slotCount ||
		!(d->slot = &d->slots[d->cards[d->selectedCard]]) ||
		!d->slot->token )
	{
		emitError( tr("Failed to login token"), ERR_get_error() );
		return false;
	}

	if( d->slot->token->loginRequired )
	{
		unsigned long err = CKR_OK;
		if( d->slot->token->secureLogin )
		{
			d->login = true;
			PinDialog *p = new PinDialog( PinDialog::Pin1PinpadType, d->sign, qApp->activeWindow() );
			p->show();
			do
			{
				wait( 1 );
				qApp->processEvents();
			} while( d->login );
			delete p;
			err = d->loginResult;
		}
		else
		{
			PinDialog p( PinDialog::Pin1Type, d->sign, qApp->activeWindow() );
			if( !p.exec() )
			{
				emitError( tr("PIN acquisition canceled."), 0, PinCanceled );
				return false;
			}
			if( PKCS11_login( d->slot, 0, p.text().toUtf8() ) < 0 )
				err = ERR_get_error();
		}
		switch( ERR_GET_REASON(err) )
		{
		case CKR_OK: break;
		case CKR_CANCEL:
		case CKR_FUNCTION_CANCELED:
			emitError( tr("PIN acquisition canceled."), 0, PinCanceled );
			return false;
		case CKR_PIN_INCORRECT:
			emitError( tr("PIN Incorrect"), 0, PinIncorrect );
			return false;
		case CKR_PIN_LOCKED:
			emitError( tr("PIN Locked"), 0, PinLocked );
			return false;
		default:
			emitError( tr("Failed to login token"), err );
			return false;
		}
	}

	PKCS11_CERT *certs;
	unsigned int certCount;
	if( PKCS11_enumerate_certs( d->slot->token, &certs, &certCount ) )
	{
		emitError( tr("Failed to decrypt document"), ERR_get_error() );
		return false;
	}
	if( !certCount || !&certs[0] )
	{
		emitError( tr("Failed to decrypt document") + "\nNo sertificates", 0 );
		return false;
	}

	PKCS11_KEY *key = PKCS11_find_key( &certs[0] );
	if( !key )
	{
		emitError( tr("Failed to decrypt document") + "\nNo keys", ERR_get_error() );
		return false;
	}

	out.resize( in.size() );
	int size = PKCS11_private_decrypt(
		in.size(), (const unsigned char*)in.constData(), (unsigned char*)out.data(), key, CKM_RSA_PKCS );
	if( size )
		out.resize( size );
	else
		emitError( tr("Failed to decrypt document"), ERR_get_error() );
	return size;
}

void Poller::emitError( const QString &msg, unsigned long err, ErrorCode code )
{
	d->code = code;
	if( err )
		Q_EMIT error( msg + "\n" + QString::fromUtf8( ERR_error_string( err, NULL ) ), quint8(code) );
	else
		Q_EMIT error( msg, quint8(code) );
}

Poller::ErrorCode Poller::errorCode() const { return d->code; }

bool Poller::loadDriver()
{
	char driver[200];
	qsnprintf( driver, sizeof(driver), "DIGIDOC_DRIVER_%d_FILE",
		ConfigItem_lookup_int( "DIGIDOC_DEFAULT_DRIVER", 1 ) );

	if( !d->handle &&
		(!(d->handle = PKCS11_CTX_new()) || PKCS11_CTX_load( d->handle, ConfigItem_lookup(driver) )) )
	{
		PKCS11_CTX_free( d->handle );
		d->handle = 0;
		return false;
	}
	if( !isRunning() )
		start();
	return true;
}

void Poller::read()
{
	d->cards.clear();
	if( d->slotCount )
	{
		PKCS11_release_all_slots( d->handle, d->slots, d->slotCount );
		d->slotCount = 0;
	}

	if( PKCS11_enumerate_slots( d->handle, &d->slots, &d->slotCount ) )
	{
		d->sign = QSslCertificate();
		d->selectedCard.clear();
		Q_EMIT dataChanged( d->cards.keys(), d->selectedCard, d->sign );
		return;
	}

	for( unsigned int i = 0; i < d->slotCount; ++i )
	{
		PKCS11_SLOT* slot = &d->slots[i];
		if( !slot->token )
			continue;

		QString serialNumber = QByteArray( (const char*)slot->token->serialnr, 16 ).trimmed();
		if( !d->cards.contains( serialNumber ) )
			d->cards[serialNumber] = i;
	}

	if( !d->selectedCard.isEmpty() && !d->cards.contains( d->selectedCard ) )
	{
		d->sign = QSslCertificate();
		d->selectedCard.clear();
	}
	Q_EMIT dataChanged( d->cards.keys(), d->selectedCard, d->sign );

	if( d->selectedCard.isEmpty() && !d->cards.isEmpty() )
		selectCert( d->cards.keys().first() );
}

void Poller::run()
{
	d->terminate = false;

	d->cards["loading"] = 0;
	d->selectedCard = "loading";
	d->sign = QSslCertificate();
	Q_EMIT dataChanged( d->cards.keys(), d->selectedCard, d->sign );

	if( !loadDriver() )
	{
		emitError( tr("Failed to load PKCS#11 module"), 0 );
		return;
	}

	while( !d->terminate )
	{
		if( d->m.tryLock() )
		{
			read();
			if( !d->select.isEmpty() && d->cards.contains( d->select ) )
				selectCert( d->select );
			d->select.clear();
			d->m.unlock();
		}

		if( d->login )
		{
			d->loginResult = CKR_OK;
			if( PKCS11_login( d->slot, 0, NULL ) < 0 )
				d->loginResult = ERR_get_error();
			d->login = false;
		}

		sleep( 1 );
	}
}

void Poller::selectCard( const QString &card ) { d->select = card; }

void Poller::selectCert( const QString &card )
{
	d->selectedCard = card;
	d->sign = QSslCertificate();
	Q_EMIT dataChanged( d->cards.keys(), d->selectedCard, d->sign );
	PKCS11_CERT* certs;
	unsigned int numberOfCerts;
	for( unsigned int i = 0; i < d->slotCount; ++i )
	{
		PKCS11_SLOT* slot = &d->slots[i];
		if( !slot->token ||
			d->selectedCard != QByteArray( (const char*)slot->token->serialnr, 16 ).trimmed() ||
			PKCS11_enumerate_certs( slot->token, &certs, &numberOfCerts ) ||
			numberOfCerts <= 0 )
			continue;

		SslCertificate cert = SslCertificate::fromX509( Qt::HANDLE((&certs[0])->x509) );
		if( cert.keyUsage().keys().contains( SslCertificate::DataEncipherment ) )
		{
			d->sign = cert;
			d->cards[d->selectedCard] = i;
			break;
		}
	}
	Q_EMIT dataChanged( d->cards.keys(), d->selectedCard, d->sign );
}

void Poller::unloadDriver()
{
	d->terminate = true;
	wait();
	if( d->slotCount )
		PKCS11_release_all_slots( d->handle, d->slots, d->slotCount );
	d->slotCount = 0;
	if( d->handle )
	{
		PKCS11_CTX_unload( d->handle );
		PKCS11_CTX_free( d->handle );
		d->handle = 0;
	}
}
