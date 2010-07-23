/*
 * QEstEidCommon
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

#pragma once

#include <QObject>

class QSslCertificate;
class QStringList;
class QUrl;

class Common: public QObject
{
	Q_OBJECT
public:
	enum CertType
	{
		AuthCert,
		SignCert,
	};
	Common( QObject *parent = 0 );

	static bool canWrite( const QString &filename );
	static QString fileSize( quint64 bytes );
	static void showHelp( const QString &msg );
	static bool startDetached( const QString &program );
	static bool startDetached( const QString &program, const QStringList &arguments );
	static QString tokenInfo( CertType type, const QString &card, const QSslCertificate &cert );

public Q_SLOTS:
	void browse( const QUrl &url );
	void mailTo( const QUrl &url );
};
