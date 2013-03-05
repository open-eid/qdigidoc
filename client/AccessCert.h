/*
 * QDigiDocClient
 *
 * Copyright (C) 2009-2013 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009-2013 Raul Metsma <raul@innovaatik.ee>
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

#include <QtCore/QtGlobal>
#if QT_VERSION >= 0x050000
#include <QtWidgets/QMessageBox>
#else
#include <QtGui/QMessageBox>
#endif

class QSslCertificate;
class QSslKey;
class AccessCertPrivate;
class AccessCert: public QMessageBox
{
	Q_OBJECT

public:
	explicit AccessCert( QWidget *parent = 0 );
	~AccessCert();

	bool download( bool noCard );
	bool validate();

	static QSslCertificate cert();
	static QSslKey key();
	bool installCert( const QByteArray &data, const QString &password );
	void remove();

private:
	QString link() const;
	void showWarning( const QString &msg );
	bool showWarning2( const QString &msg );

	AccessCertPrivate *d;
};
