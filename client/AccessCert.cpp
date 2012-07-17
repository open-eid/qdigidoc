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

#include "AccessCert.h"

#include "Application.h"
#include "QSigner.h"

#ifdef Q_OS_WIN
#include <common/QCNG.h>
#endif
#include <common/QPKCS11.h>
#include <common/SslCertificate.h>
#include <common/sslConnect.h>
#include <common/TokenData.h>

#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QScopedPointer>
#include <QtCore/QUrl>
#include <QtCore/QXmlStreamReader>
#include <QtGui/QDesktopServices>
#include <QtGui/QLabel>
#include <QtGui/QMessageBox>

AccessCert::AccessCert( QWidget *parent )
:	QObject( parent )
,	m_parent( parent )
{
	m_cert = Application::confValue( Application::PKCS12Cert ).toString();
	m_pass = Application::confValue( Application::PKCS12Pass ).toString();
}

AccessCert::~AccessCert()
{
	Application::setConfValue( Application::PKCS12Cert, m_cert );
	Application::setConfValue( Application::PKCS12Pass, m_pass );
}

bool AccessCert::download( bool noCard )
{
	if( noCard )
	{
		QDesktopServices::openUrl( QUrl( tr("http://www.sk.ee/toend/") ) );
		return false;
	}

	QMessageBox d( QMessageBox::Information, tr("Server access certificate"),
		tr("Hereby I agree to terms and conditions of validity confirmation service and "
		   "will use the service in extent of 10 signatures per month. If you going to "
		   "exceed the limit of 10 signatures per month or/and will use the service for "
		   "commercial purposes, please refer to IT support of your company. Additional "
		   "information is available from <a href=\"%1\">%1</a> or phone 1777")
			.arg( tr("http://www.id.ee/kehtivuskinnitus") ),
		QMessageBox::Help, m_parent );
	d.addButton( tr("Agree"), QMessageBox::AcceptRole );
	if( QLabel *label = d.findChild<QLabel*>() )
		label->setOpenExternalLinks( true );
	if( d.exec() == QMessageBox::Help )
	{
		QDesktopServices::openUrl( QUrl( tr("http://www.id.ee/kehtivuskinnitus") ) );
		return false;
	}

	QSigner *s = qApp->signer();
	QPKCS11 *p = qobject_cast<QPKCS11*>(reinterpret_cast<QObject*>(s->handle()));
#ifdef Q_OS_WIN
	QCNG *c = qobject_cast<QCNG*>(reinterpret_cast<QObject*>(s->handle()));
	if( !p && !s )
		return false;
#endif

	s->lock();
	Qt::HANDLE key = 0;
	TokenData token;
	if( p )
	{
		bool retry = false;
		do
		{
			retry = false;
			token = p->selectSlot( s->token().card(), SslCertificate::KeyUsageNone, SslCertificate::ClientAuth );
			QPKCS11::PinStatus status = p->login( token );
			switch( status )
			{
			case QPKCS11::PinOK: break;
			case QPKCS11::PinCanceled:
				s->unlock();
				return false;
			case QPKCS11::PinIncorrect:
				showWarning( QPKCS11::errorString( status ) );
				retry = true;
				break;
			default:
				showWarning( tr("Error downloading server access certificate!") + "\n" + QPKCS11::errorString( status ) );
				s->unlock();
				return false;
			}
		}
		while( retry );
		key = p->key();
	}
	else
	{
#ifdef Q_OS_WIN
		foreach( const SslCertificate &cert, c->certs() )
			if( cert.isValid() && cert.enhancedKeyUsage().contains( SslCertificate::ClientAuth ) )
				token = c->selectCert( cert );
		key = c->key();
#else
		return false;
#endif
	}

	QScopedPointer<SSLConnect> ssl( new SSLConnect );
	ssl->setToken( token.cert(), key );
	QByteArray result = ssl->getUrl( SSLConnect::AccessCert );
	if( !ssl->errorString().isEmpty() )
	{
		showWarning( tr("Error downloading server access certificate!") + "\n" + ssl->errorString() );
		return false;
	}
	s->unlock();

	if( result.isEmpty() )
	{
		showWarning( tr("Empty result!") );
		return false;
	}

	QString status, cert, pass, message;
	QXmlStreamReader xml( result );
	while( xml.readNext() != QXmlStreamReader::Invalid )
	{
		if( !xml.isStartElement() )
			continue;
		if( xml.name() == "StatusCode" )
			status = xml.readElementText();
		else if( xml.name() == "MessageToDisplay" )
			message = xml.readElementText();
		else if( xml.name() == "TokenData" )
			cert = xml.readElementText();
		else if( xml.name() == "TokenPassword" )
			pass = xml.readElementText();
	}

	if( status.isEmpty() )
	{
		showWarning( tr("Error parsing server access certificate result!") );
		return false;
	}

	switch( status.toInt() )
	{
	case 1: //need to order cert manually from SK web
		QDesktopServices::openUrl( QUrl( tr("http://www.sk.ee/toend/") ) );
		return false;
	case 2: //got error, show message from MessageToDisplay element
		showWarning( tr("Error downloading server access certificate!\n%1").arg( message ) );
		return false;
	default: break; //ok
	}

	if ( cert.isEmpty() )
	{
		showWarning( tr("Error reading server access certificate - empty content!") );
		return false;
	}

	QString path = QDesktopServices::storageLocation( QDesktopServices::DataLocation );
	if ( !QDir( path ).exists() )
		QDir().mkpath( path );

	QFile f( QString( "%1/%2.p12" ).arg( path,
		SslCertificate( qApp->signer()->token().cert() ).subjectInfo( "serialNumber" ) ) );
	if ( !f.open( QIODevice::WriteOnly|QIODevice::Truncate ) )
	{
		showWarning( tr("Failed to save server access certificate file to %1!\n%2")
			.arg( f.fileName() )
			.arg( f.errorString() ) );
		return false;
	}
	f.write( QByteArray::fromBase64( cert.toLatin1() ) );

	Application::setConfValue( Application::PKCS12Cert, m_cert = QDir::toNativeSeparators( f.fileName() ) );
	Application::setConfValue( Application::PKCS12Pass, m_pass = pass );
	return true;
}

void AccessCert::showWarning( const QString &msg )
{ QMessageBox::warning( m_parent, tr( "Server access certificate" ), msg ); }

bool AccessCert::showWarning2( const QString &msg )
{
	return QMessageBox::No == QMessageBox::warning( m_parent, tr( "Server access certificate" ),
		msg, QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes );
}

bool AccessCert::validate()
{
	if( Application::confValue( Application::PKCS12Disable, false ).toBool() )
		return true;
	m_cert = Application::confValue( Application::PKCS12Cert ).toString();
	m_pass = Application::confValue( Application::PKCS12Pass ).toString();

	QFile f( m_cert );
	if( !f.exists() )
	{
		if( showWarning2( tr("Did not find any server access certificate!\nStart downloading?") ) )
		{
			Application::setConfValue( Application::PKCS12Cert, QVariant() );
			Application::setConfValue( Application::PKCS12Pass, QVariant() );
			return true;
		}
	}
	else if( !f.open( QIODevice::ReadOnly ) )
	{
		if( showWarning2( tr("Failed to read server access certificate!\nStart downloading?") ) )
		{
			Application::setConfValue( Application::PKCS12Cert, QVariant() );
			Application::setConfValue( Application::PKCS12Pass, QVariant() );
			return true;
		}
	}
	else
	{
		PKCS12Certificate p12Cert( &f, m_pass.toLatin1() );

		if( p12Cert.error() == PKCS12Certificate::InvalidPasswordError )
		{
			if( showWarning2( tr("Server access certificate password is not valid!\nStart downloading?") ) )
			{
				Application::setConfValue( Application::PKCS12Cert, QVariant() );
				Application::setConfValue( Application::PKCS12Pass, QVariant() );
				return true;
			}
		}
		else if( !p12Cert.certificate().isValid() )
		{
			if( showWarning2( tr("Server access certificate is not valid!\nStart downloading?") ) )
			{
				Application::setConfValue( Application::PKCS12Cert, QVariant() );
				Application::setConfValue( Application::PKCS12Pass, QVariant() );
				return true;
			}
		}
		else if( p12Cert.certificate().expiryDate() < QDateTime::currentDateTime().addDays( 8 ) &&
			!showWarning2( tr("Server access certificate is about to expire!\nStart downloading?") ) )
			return false;
		else
			return true;
	}

	return false;
}
