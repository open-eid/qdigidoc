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

#include "ui_MainWindow.h"

class CKey;
class CryptoDoc;

class MainWindow: public QWidget, private Ui::MainWindow
{
	Q_OBJECT

public:
	explicit MainWindow( QWidget *parent = 0 );

	void closeDoc();

private Q_SLOTS:
	void buttonClicked( int button );
	void changeCard( QAction *a );
	void changeLang( QAction *a );
	void on_introCheck_stateChanged( int state );
	void on_languages_activated( int index );
	void open( const QStringList &params );
	void parseLink( const QString &url );
	void removeDocument( int index );
	void showCardStatus();
	void removeKey( int id );
	void updateView();

private:
	enum Pages {
		Home,
		Intro,
		View,
	};
	enum Buttons {
		HeadAbout,
		HeadSettings,
		HeadHelp,
		HomeCreate,
		HomeView,
		IntroBack,
		IntroNext,
		ViewClose,
		ViewCrypt,
	};
	bool addFile( const QString &file );
	bool event( QEvent *e );
	void dragEnterEvent( QDragEnterEvent *e );
	void dropEvent( QDropEvent *e );
	void retranslate();
	void setCurrentPage( Pages page );

	QActionGroup *cardsGroup;
	CryptoDoc	*doc;
	QStringList lang, params;
	QPushButton *introNext, *viewCrypt;
};
