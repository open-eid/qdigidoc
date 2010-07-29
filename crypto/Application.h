/*
 * QDigiDocCrypto
 *
 * Copyright (C) 2009,2010 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009,2010 Raul Metsma <raul@innovaatik.ee>
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

#include <QApplication>

#if defined(qApp)
#undef qApp
#endif
#define qApp (static_cast<Application*>(QCoreApplication::instance()))

class Poller;
class QSslCertificate;
class ApplicationPrivate;
class Application: public QApplication
{
    Q_OBJECT

public:
	explicit Application( int &argc, char **argv );
	~Application();

	QString activeCard() const;
	QSslCertificate authCert() const;
	void loadTranslation( const QString &lang );
	Poller* poller() const;
	QStringList presentCards() const;

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
		const QSslCertificate &auth );

private:
	bool event( QEvent *e );

	ApplicationPrivate *d;
};
