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

#include "LdapSearch.h"

#include "CryptoDoc.h"

#include <QTimerEvent>

#ifndef Q_OS_WIN32
#define LDAP_TIMEVAL timeval
#endif

LdapSearch::LdapSearch( QObject *parent )
:	QObject( parent )
{
	ldap = ldap_init( "ldap.sk.ee", 389 );
	if( !ldap )
	{
		setLastError( tr("Failed to init ldap"), -1 );
		return;
	}

	int err = ldap_simple_bind_s( ldap, NULL, NULL );
	if( err )
		setLastError( tr("Failed to init ldap"), err );
}

LdapSearch::~LdapSearch() { if( ldap ) ldap_unbind_s( ldap ); }

void LdapSearch::search( const QString &search )
{
	char *attrs[3] = {
		const_cast<char*>("cn"),
		const_cast<char*>("userCertificate;binary"), '\0' };

	int err = ldap_search_ext( ldap, "c=EE", LDAP_SCOPE_SUBTREE,
		const_cast<char*>(search.toUtf8().constData()), attrs, 0, NULL, NULL, NULL, 0, &msg_id );
	if( err )
		setLastError( tr("Failed to init ldap search"), err );
	else
		startTimer( 1000 );
}

void LdapSearch::setLastError( const QString &msg, int err )
{
	QString res = msg;
	if( err != -1 )
	{
		res += "<br />";
		switch( err )
		{
		case LDAP_UNAVAILABLE:
			res += tr("LDAP server is unavailable.");
			break;
		default:
			res += tr( "Error Code: %1 (%2)" ).arg( err ).arg( ldap_err2string( err ) );
			break;
		}
	}
	Q_EMIT error( res );
}

void LdapSearch::timerEvent( QTimerEvent *e )
{
	LDAPMessage *result = 0;
	LDAP_TIMEVAL t = { 5, 0 };
	int err = ldap_result( ldap, msg_id, LDAP_MSG_ALL, &t, &result );
	//int count = ldap_count_messages( ldap, result );
	if( err != LDAP_RES_SEARCH_ENTRY && err != LDAP_RES_SEARCH_RESULT )
	{
		setLastError( tr("Failed to get result"), err );
		killTimer( e->timerId() );
		return;
	}

	LDAPMessage *entry = ldap_first_entry( ldap, result );
	if( entry == NULL )
	{
		setLastError( tr("Empty result"), -1 );
		ldap_msgfree( result );
		killTimer( e->timerId() );
		return;
	}

	QList<CKey> list;
	do
	{
		char **name = 0;
		berval **cert = 0;
		BerElement *pos;
		char *attr = ldap_first_attribute( ldap, entry, &pos );
		do
		{
			if( qstrcmp( attr, "cn" ) == 0 )
				name = ldap_get_values( ldap, entry, attr );
			else if( qstrcmp( attr, "userCertificate;binary" ) == 0 )
				cert = ldap_get_values_len( ldap, entry, attr );
			ldap_memfree( attr );
		}
		while( (attr = ldap_next_attribute( ldap, entry, pos ) ) );
		ber_free( pos, 0 );

		if( ldap_count_values(name) && ldap_count_values_len(cert) )
		{
			CKey key;
			key.cert = QSslCertificate( QByteArray( cert[0]->bv_val, cert[0]->bv_len ), QSsl::Der );
			key.recipient = QString::fromUtf8( name[0] );
			list << key;
		}

		ldap_value_free( name );
		ldap_value_free_len( cert );
	}
	while( (entry = ldap_next_entry( ldap, entry )) );

	Q_EMIT searchResult( list );
	ldap_msgfree( result );
	killTimer( e->timerId() );
}
