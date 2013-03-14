/*
 * QDigiDocClient
 *
 * Copyright (C) 2009-2012 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009-2012 Raul Metsma <raul@innovaatik.ee>
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
	QSignerPrivate():
#ifdef Q_OS_WIN
		csp(0),
		cng(0),
#endif
		pkcs11(0), terminate(false) {}

#ifdef Q_OS_WIN
	QCSP			*csp;
	QCNG			*cng;
#endif
	QPKCS11			*pkcs11;
	TokenData		t;
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
	d->t.setCard( "loading" );
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
#ifdef Q_OS_WIN
	if( d->csp ) return CAPI;
	if( d->cng ) return CNG;
#endif
	return PKCS11;
}

X509Cert QSigner::cert() const
{
	if( d->t.cert().isNull() )
		throw Exception( __FILE__, __LINE__, QSigner::tr("Sign certificate is not selected").toUtf8().constData() );
	try
	{
		QByteArray der = d->t.cert().toDer();
		return X509Cert(std::vector<unsigned char>(der.constData(), der.constData() + der.size()));
	}
	catch(const Exception &e)
	{
		throw Exception( __FILE__, __LINE__, QSigner::tr("Sign certificate is not selected").toUtf8().constData(), e );
	}

	return X509Cert();
}

Qt::HANDLE QSigner::handle() const
{
#ifdef Q_OS_WIN
	if( d->csp ) return Qt::HANDLE(d->csp);
	if( d->cng ) return Qt::HANDLE(d->cng);
#endif
	return Qt::HANDLE(d->pkcs11);
}

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
			QStringList cards, readers;
#ifdef Q_OS_WIN
			QCNG::Certs certs;
			if( d->csp )
			{
				cards = d->csp->containers( SslCertificate::NonRepudiation );
				readers << "blank";
			}
			if( d->cng )
			{
				certs = d->cng->certs();
				for( QCNG::Certs::const_iterator i = certs.constBegin(); i != certs.constEnd(); ++i )
					if( i.key().keyUsage().contains( SslCertificate::NonRepudiation ) )
						cards << i.value();
				readers << d->cng->readers();
			}
#endif
			if( d->pkcs11 )
			{
				cards = d->pkcs11->cards();
				readers = d->pkcs11->readers();
			}
			bool update = d->t.cards() != cards; // check if cards have inserted/removed, update list
			d->t.setCards( cards );

			if( d->t.readers() != readers )
			{
				d->t.setReaders( readers );
				update = true;
			}

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
					d->t = d->csp->selectCert( d->t.card(), SslCertificate::NonRepudiation );
				else if( d->cng )
				{
					for( QCNG::Certs::const_iterator i = certs.constBegin(); i != certs.constEnd(); ++i )
					{
						if( i.value() == d->t.card() &&
							i.key().keyUsage().contains( SslCertificate::NonRepudiation ) )
						{
							d->t = d->cng->selectCert( i.key() );
							break;
						}
					}
				}
				else
#endif
					d->t = d->pkcs11->selectSlot( d->t.card(), SslCertificate::NonRepudiation, SslCertificate::EnhancedKeyUsageNone );
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

void QSigner::showWarning( const QString &msg )
{ qApp->showWarning( msg ); }

void QSigner::sign(const std::string &method, const std::vector<unsigned char> &digest,
	std::vector<unsigned char> &signature )
{
	QMutexLocker locker( &d->m );
	if( !d->t.cards().contains( d->t.card() ) || d->t.cert().isNull() )
		throwException( tr("Signing certificate is not selected."), Exception::NoException, __LINE__ );

	int type = NID_sha1;
	if( method == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224" ) type = NID_sha224;
	if( method == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" ) type = NID_sha256;
	if( method == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" ) type = NID_sha384;
	if( method == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" ) type = NID_sha512;

	QByteArray sig;
	if( d->pkcs11 )
	{
		QPKCS11::PinStatus status = d->pkcs11->login( d->t );
		switch( status )
		{
		case QPKCS11::PinOK: break;
		case QPKCS11::PinCanceled:
			throwException( tr("Failed to login token") + " " + QPKCS11::errorString( status ), Exception::PINCanceled, __LINE__ );
		case QPKCS11::PinIncorrect:
			throwException( tr("Failed to login token") + " " + QPKCS11::errorString( status ), Exception::PINIncorrect, __LINE__ );
		case QPKCS11::PinLocked:
			locker.unlock();
			reload();
			throwException( tr("Failed to login token") + " " + QPKCS11::errorString( status ), Exception::PINLocked, __LINE__ );
		default:
			throwException( tr("Failed to login token") + " " + QPKCS11::errorString( status ), Exception::NoException, __LINE__ );
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
		sig = d->cng->sign( type, QByteArray( (const char*)&digest[0], digest.size() ) );
		if( d->cng->lastError() == QCNG::PinCanceled )
			throwException( tr("Failed to login token"), Exception::PINCanceled, __LINE__ );
	}
#endif

	locker.unlock();
	reload();
	if( sig.isEmpty() )
		throwException( tr("Failed to sign document"), Exception::NoException, __LINE__ );
	signature.resize( sig.size() );
	qMemCopy( &signature[0], sig.constData(), sig.size() );
}

void QSigner::throwException( const QString &msg, Exception::ExceptionCode code, int line )
{
	QString t = msg;
	Exception e( __FILE__, line, t.toUtf8().constData() );
	e.setCode( code );
	throw e;
}

TokenData QSigner::token() const { return d->t; }

void QSigner::unlock() { d->m.unlock(); reload(); }
