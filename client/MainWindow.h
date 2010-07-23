/*
 * QDigiDocClient
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

#include "ui_MainWindow.h"

#include <QStringList>

class DigiDoc;
class QTranslator;

class MainWindow: public QWidget, private Ui::MainWindow
{
	Q_OBJECT

public:
	MainWindow( QWidget *parent = 0 );

	bool isLoaded() const;

private Q_SLOTS:
	void buttonClicked( int button );
	void changeCard( QAction *a );
	void changeLang( QAction *a );
	void closeDoc();
	void enableSign();
	void on_introCheck_stateChanged( int state );
	void on_languages_activated( int index );
	void parseLink( const QString &link );
	void removeDocument( unsigned int index );
	void showCardStatus();
	void showSettings();
	void showWarning( const QString &msg );
	void viewSignaturesRemove( unsigned int num );

private:
	enum Pages {
		Home,
		Intro,
		Sign,
		View,
	};
	enum Buttons {
		HeadSettings,
		HeadHelp,
		HomeCrypt,
		HomeSign,
		IntroBack,
		IntroNext,
		SignCancel,
		SignSign,
		HomeView,
		ViewAddSignature,
		ViewClose,
	};
	bool addFile( const QString &file );
	void dragEnterEvent( QDragEnterEvent *e );
	void dropEvent( QDropEvent *e );
	bool eventFilter( QObject *o, QEvent *e );
	void setCurrentPage( Pages page );

	QActionGroup *cardsGroup;
	QAction *closeAction;
	DigiDoc	*doc;
	QTranslator *appTranslator, *commonTranslator, *qtTranslator;
	QStringList lang, params;
	QPushButton *introNext, *signButton, *viewAddSignature;
	bool m_loaded, quitOnClose;
};
