/*
 * QDigiDocClient
 *
 * Copyright (C) 2009-2012 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009-2012 Raul Metsma <raul@innovaatik.ee>
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

#include <QtGui/QWidget>

namespace Ui { class SettingsDialog; }

class SettingsDialog: public QWidget
{
	Q_OBJECT

public:
	explicit SettingsDialog( QWidget *parent = 0 );
	~SettingsDialog();

	void setP12Cert( const QString &cert );
	void setPage( int page );

	static void saveSignatureInfo(
		const QString &role,
		const QString &resolution,
		const QString &city,
		const QString &state,
		const QString &country,
		const QString &zip,
		bool force = false );

private Q_SLOTS:
	void on_p12Button_clicked();
	void on_p12Install_clicked();
#ifndef APPSTORE
	void on_selectDefaultDir_clicked();
#endif
	void on_showP12Cert_clicked();
	void on_typeBDoc_clicked( bool checked );
	void save();

private:
	bool eventFilter( QObject *o, QEvent *e );

	Ui::SettingsDialog *d;
};
