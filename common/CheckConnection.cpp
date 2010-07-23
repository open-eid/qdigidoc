/*
 * QEstEidCommon
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

#include "CheckConnection.h"

#include "Settings.h"

#include <QCoreApplication>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QNetworkRequest>

CheckConnection::CheckConnection( QObject *parent )
:	QNetworkAccessManager( parent )
{
	connect( this, SIGNAL(finished(QNetworkReply*)), SLOT(stop(QNetworkReply*)) );
	Settings s;
	s.beginGroup( "Client" );
	if( !s.value( "proxyHost" ).toString().isEmpty() )
	{
		setProxy( QNetworkProxy(
			QNetworkProxy::HttpProxy,
			s.value( "proxyHost" ).toString(),
			s.value( "proxyPort" ).toInt(),
			s.value( "proxyUser" ).toString(),
			s.value( "proxyPass" ).toString() ) );
	}
}

bool CheckConnection::check( const QString &url )
{
	running = true;
	QNetworkReply *reply = get( QNetworkRequest( QUrl( url ) ) );

	while( running )
		qApp->processEvents();

	switch( reply->error() )
	{
	case QNetworkReply::NoError:
		return true;
	case QNetworkReply::ProxyConnectionRefusedError:
	case QNetworkReply::ProxyConnectionClosedError:
	case QNetworkReply::ProxyNotFoundError:
	case QNetworkReply::ProxyTimeoutError:
		m_error = tr("Check proxy settings");
		return false;
	case QNetworkReply::ProxyAuthenticationRequiredError:
		m_error = tr("Check proxy username and password");
		return false;
	default:
		m_error = tr("Check internet connection");
		return false;
	}
}

QString CheckConnection::error() const { return m_error; }

void CheckConnection::stop( QNetworkReply * ) { running = false; }
