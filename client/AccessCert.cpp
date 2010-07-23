/*
 * QDigiDocClient
 *
 * Copyright (C) 2009 Jargo Kőster <jargo@innovaatik.ee>
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

#include "AccessCert.h"

#include "DigiDoc.h"
#include "QSigner.h"

#include "common/SslCertificate.h"
#include "common/sslConnect.h"

#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QDomElement>
#include <QDomNodeList>
#include <QFile>
#include <QMessageBox>
#include <QUrl>

AccessCert::AccessCert( QWidget *parent )
:	QObject( parent )
,	m_parent( parent )
{
	m_cert = DigiDoc::getConfValue( DigiDoc::PKCS12Cert );
	m_pass = DigiDoc::getConfValue( DigiDoc::PKCS12Pass );
}

AccessCert::~AccessCert()
{
	DigiDoc::setConfValue( DigiDoc::PKCS12Cert, m_cert );
	DigiDoc::setConfValue( DigiDoc::PKCS12Pass, m_pass );
}

bool AccessCert::download( QSigner *signer, const QString &card, const QString &filename )
{
	signer->lock();
	SSLConnect *ssl = new SSLConnect();
	ssl->setPKCS11( DigiDoc::getConfValue( DigiDoc::PKCS11Module ), false );
	ssl->setCard( card );

	bool retry = false;
	do
	{
		retry = false;
		ssl->waitForFinished( SSLConnect::AccessCert );
		switch( ssl->error() )
		{
		case SSLConnect::PinCanceledError:
			delete ssl;
			signer->unlock();
			return false;
		case SSLConnect::PinInvalidError:
			showWarning( ssl->errorString() );
			retry = true;
			break;
		default:
			if( !ssl->errorString().isEmpty() )
			{
				showWarning( tr("Error downloading server access certificate!\n%1").arg( ssl->errorString() ) );
				delete ssl;
				signer->unlock();
				return false;
			}
			break;
		}
	}
	while( retry );

	QByteArray result = ssl->result();
	delete ssl;
	signer->unlock();

	if( result.isEmpty() )
	{
		showWarning( tr("Empty result!") );
		return false;
	}

	QDomDocument domDoc;
	if( !domDoc.setContent( QString::fromUtf8( result ) ) )
	{
		showWarning( tr("Error parsing server access certificate result!") );
		return false;
	}

	QDomElement e = domDoc.documentElement();
	QDomNodeList status = e.elementsByTagName( "StatusCode" );
	if( status.isEmpty() )
	{
		showWarning( tr("Error parsing server access certificate result!") );
		return false;
	}

	switch( status.item(0).toElement().text().toInt() )
	{
	case 1: //need to order cert manually from SK web
		QDesktopServices::openUrl( QUrl( "http://www.sk.ee/toend/" ) );
		return false;
	case 2: //got error, show message from MessageToDisplay element
		showWarning( tr("Error downloading server access certificate!\n%1")
			.arg( e.elementsByTagName( "MessageToDisplay" ).item(0).toElement().text() ) );
		return false;
	default: break; //ok
	}

	QString cert = e.elementsByTagName( "TokenData" ).item(0).toElement().text();
	if ( cert.isEmpty() )
	{
		showWarning( tr("Error reading server access certificate - empty content!") );
		return false;
	}

	QString path = QDesktopServices::storageLocation( QDesktopServices::DataLocation );
	if ( !QDir( path ).exists() )
		QDir().mkpath( path );

	QFile f( QString( "%1/%2.p12" ).arg( path ).arg( filename ) );
	if ( !f.open( QIODevice::WriteOnly|QIODevice::Truncate ) )
	{
		showWarning( tr("Failed to save server access certificate file to %1!\n%2")
			.arg( f.fileName() )
			.arg( f.errorString() ) );
		return false;
	}
	f.write( QByteArray::fromBase64( cert.toLatin1() ) );

	DigiDoc::setConfValue( DigiDoc::PKCS12Cert, m_cert = f.fileName() );
	DigiDoc::setConfValue( DigiDoc::PKCS12Pass, m_pass = e.elementsByTagName( "TokenPassword" ).item(0).toElement().text() );
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
	m_cert = DigiDoc::getConfValue( DigiDoc::PKCS12Cert );
	m_pass = DigiDoc::getConfValue( DigiDoc::PKCS12Pass );

	QFile f( m_cert );
	if( !f.exists() )
	{
		if( showWarning2( tr("Did not find any server access certificate!\nStart downloading?") ) )
		{
			DigiDoc::setConfValue( DigiDoc::PKCS12Cert, QVariant() );
			DigiDoc::setConfValue( DigiDoc::PKCS12Pass, QVariant() );
			return true;
		}
	}
	else if( !f.open( QIODevice::ReadOnly ) )
	{
		if( showWarning2( tr("Failed to read server access certificate!\nStart downloading?") ) )
		{
			DigiDoc::setConfValue( DigiDoc::PKCS12Cert, QVariant() );
			DigiDoc::setConfValue( DigiDoc::PKCS12Pass, QVariant() );
			return true;
		}
	}
	else
	{
		PKCS12Certificate p12Cert( &f, m_pass.toLatin1() );

		if( p12Cert.error() == PKCS12Certificate::InvalidPassword )
		{
			if( showWarning2( tr("Server access certificate password is not valid!\nStart downloading?") ) )
			{
				DigiDoc::setConfValue( DigiDoc::PKCS12Cert, QVariant() );
				DigiDoc::setConfValue( DigiDoc::PKCS12Pass, QVariant() );
				return true;
			}
		}
		else if( !p12Cert.certificate().isValid() )
		{
			if( showWarning2( tr("Server access certificate is not valid!\nStart downloading?") ) )
			{
				DigiDoc::setConfValue( DigiDoc::PKCS12Cert, QVariant() );
				DigiDoc::setConfValue( DigiDoc::PKCS12Pass, QVariant() );
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
