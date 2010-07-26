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

#pragma once

#include "qtsingleapplication/src/QtSingleApplication"

#include <QVariant>

#if defined(qApp)
#undef qApp
#endif
#define qApp (static_cast<Application*>(QCoreApplication::instance()))

class QSigner;
class QSslCertificate;
class ApplicationPrivate;
class Application: public QtSingleApplication
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
	};

	explicit Application( int &argc, char **argv );
	~Application();

	QString activeCard() const;
	void loadTranslation( const QString &lang );
	QStringList presentCards() const;
	QSslCertificate signCert() const;
	QSigner* signer() const;

	static QString confValue( ConfParameter parameter, const QVariant &value = QVariant() );
	static void setConfValue( ConfParameter parameter, const QVariant &value );
#ifdef Q_OS_LINUX
	static QByteArray fileEncoder( const QString &filename ) { return filename.toUtf8(); }
	static QString fileDecoder( const QByteArray &filename ) { return QString::fromUtf8( filename ); }
#endif

public Q_SLOTS:
	void showSettings();
	void showWarning( const QString &msg );

Q_SIGNALS:
	void dataChanged();

private Q_SLOTS:
	void closeWindow();
	void dataChanged( const QStringList &cards, const QString &card,
		const QSslCertificate &sign );
	void parseArgs( const QString &msg );

private:
	bool event( QEvent *e );

	ApplicationPrivate *d;
};
