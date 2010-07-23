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

#include <QVariant>

class CertificateDialogPrivate;
class QSslCertificate;

class CertificateDialog: public QDialog
{
	Q_OBJECT
public:
	CertificateDialog( QWidget *parent = 0 );
	CertificateDialog( const QSslCertificate &cert, QWidget *parent = 0 );
	~CertificateDialog();

	void setCertificate( const QSslCertificate &cert );

private Q_SLOTS:
	void on_parameters_itemSelectionChanged();
	void save();

private:
	void addItem( const QString &variable, const QString &value, const QVariant &valueext = QVariant() );
	QByteArray addHexSeparators( const QByteArray &data ) const;

	CertificateDialogPrivate *d;
};
