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
#include <QtWidgets/QLabel>
#include <QtWidgets/QWidget>
#else
#include <QtGui/QLabel>
#include <QtGui/QWidget>
#endif

#include "DigiDoc.h"

class QAbstractButton;
class QTreeWidget;
class SignatureDialogPrivate;

class SignatureWidget: public QLabel
{
	Q_OBJECT

public:
	explicit SignatureWidget( const DigiDocSignature &s, unsigned int signnum, QWidget *parent = 0 );

Q_SIGNALS:
	void removeSignature( unsigned int num );

private Q_SLOTS:
	void link( const QString &url );

private:
	unsigned int num;
	DigiDocSignature s;
};

class SignatureDialog: public QWidget
{
	Q_OBJECT

public:
	explicit SignatureDialog( const DigiDocSignature &signature, QWidget *parent = 0 );
	~SignatureDialog();

private Q_SLOTS:
	void on_signatureView_doubleClicked( const QModelIndex &index );
	void buttonClicked( QAbstractButton *button );

private:
	void addItem( QTreeWidget *view, const QString &variable, const QString &value );

	DigiDocSignature s;
	SignatureDialogPrivate *d;
};
