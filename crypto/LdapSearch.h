/*
 * QDigiDocCrypto
 *
 * Copyright (C) 2009 Jargo Kster <jargo@innovaatik.ee>
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

#pragma once

#include "CryptoDoc.h"

#ifdef Q_OS_WIN32
#include <Winldap.h>
#include <Winber.h>
#else
#define LDAP_DEPRECATED 1
#include <ldap.h>
#define ULONG int
#endif

class LdapSearch: public QObject
{
	Q_OBJECT

public:
	LdapSearch( QObject *parent = 0 );
	~LdapSearch();

	void search( const QString &search );

Q_SIGNALS:
	void searchResult( const QList<CKey> &result );
	void error( const QString &msg );

private:
	void timerEvent( QTimerEvent *e );
	void setLastError( const QString &msg, int err );

	LDAP *ldap;
	ULONG msg_id;
};
