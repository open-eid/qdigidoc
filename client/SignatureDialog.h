/*
 * QDigiDocClient
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

#include <QtWidgets/QLabel>
#include <QtWidgets/QDialog>

#include "DigiDoc.h"

class QAbstractButton;
class QTreeWidget;
class SignatureDialogPrivate;

class SignatureWidget: public QLabel
{
	Q_OBJECT

public:
    explicit SignatureWidget( const DigiDocSignature &s, DigiDocSignature::SignatureStatus status, unsigned int signnum, QWidget *parent = 0 );

Q_SIGNALS:
	void removeSignature( unsigned int num );

private Q_SLOTS:
	void link( const QString &url );

private:
	void mouseDoubleClickEvent( QMouseEvent *e );

	unsigned int num;
	DigiDocSignature s;
};

class SignatureDialog: public QDialog
{
	Q_OBJECT

public:
	explicit SignatureDialog( const DigiDocSignature &signature, QWidget *parent = 0 );
	~SignatureDialog();

private Q_SLOTS:
	void buttonClicked( QAbstractButton *button );
	void on_more_linkActivated( const QString &link );

private:
	void addItem( QTreeWidget *view, const QString &variable, const QString &value );
	void addItem( QTreeWidget *view, const QString &variable, const QSslCertificate &cert );
	void addItem( QTreeWidget *view, const QString &variable, const QUrl &url );

	DigiDocSignature s;
	SignatureDialogPrivate *d;
};
