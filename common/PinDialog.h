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

#include <QDialog>

#include <QRegExp>

class QLineEdit;
class QSslCertificate;

class PinDialog: public QDialog
{
	Q_OBJECT
public:
	enum PinType
	{
		Pin1Type,
		Pin2Type,
		Pin1PinpadType,
		Pin2PinpadType,
	};
	PinDialog( QWidget *parent = 0 );
	PinDialog( PinType type, const QSslCertificate &cert, QWidget *parent = 0 );
	PinDialog( PinType type, const QString &title, QWidget *parent = 0 );
	void init( PinType type, const QString &title );

	QString text() const;

private Q_SLOTS:
	void textEdited( const QString &text );

private:

	QLineEdit	*m_text;
	QPushButton	*ok;
	QRegExp		regexp;
};
