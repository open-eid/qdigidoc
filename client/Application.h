/*
 * QDigiDocClient
 *
 * Copyright (C) 2010-2013 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2010-2013 Raul Metsma <raul@innovaatik.ee>
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

#include <common/Common.h>

#include <QtCore/QVariant>

#if defined(qApp)
#undef qApp
#endif
#define qApp (static_cast<Application*>(QCoreApplication::instance()))

class QAction;
class QSigner;
class ApplicationPrivate;
class Application: public Common
{
	Q_OBJECT

public:
	enum ConfParameter
	{
		PKCS11Module,
		ProxyHost,
		ProxyPort,
		ProxyUser,
		ProxyPass,
		PKCS12Cert,
		PKCS12Pass,
		PKCS12Disable
	};

	explicit Application( int &argc, char **argv );
	~Application();

	QString lastPath() const;
	void loadTranslation( const QString &lang );
	bool notify( QObject *o, QEvent *e );
	QSigner* signer() const;
	void setLastPath( const QString &path );
	int run();

	static QVariant confValue( ConfParameter parameter, const QVariant &value = QVariant() );
	static void setConfValue( ConfParameter parameter, const QVariant &value );
	static void showWarning( const QString &msg, int err, const QString &details = QString(), const QString &search = QString() );

public Q_SLOTS:
	void showAbout();
	void showClient( const QStringList &params = QStringList() );
	void showCrypto( const QStringList &params = QStringList() );
	void showSettings( int page = 0 );
	void showWarning( const QString &msg );

private Q_SLOTS:
	void closeWindow();
	void parseArgs( const QString &msg = QString() );
	void parseArgs( const QStringList &args );

private:
	void activate( QWidget *w );
	bool event( QEvent *e );

	ApplicationPrivate *d;
};
