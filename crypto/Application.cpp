/*
 * QDigiDocCrypto
 *
 * Copyright (C) 2010 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2010 Raul Metsma <raul@innovaatik.ee>
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

#include "Application.h"

#include "MainWindow.h"
#include "Poller.h"
#include "SettingsDialog.h"
#include "version.h"

#include <common/AboutWidget.h>
#include <common/Common.h>
#include <common/TokenData.h>

#include <libdigidoc/DigiDocConfig.h>

#include <QDesktopServices>
#include <QFileInfo>
#include <QFileOpenEvent>
#include <QMessageBox>
#include <QPalette>
#include <QSslCertificate>
#include <QTranslator>

#ifdef Q_OS_LINUX
#include <QFile>
#endif

#ifdef Q_OS_MAC
#include <QMenu>
#include <QMenuBar>

void qt_mac_set_dock_menu( QMenu *menu );
#endif

class ApplicationPrivate
{
public:
	ApplicationPrivate(): poller( 0 ) {}

	TokenData	data;
	QAction		*closeAction;
#ifdef Q_OS_MAC
	QAction		*aboutAction, *newWindowAction, *settingsAction;
	QMenu		*menu;
	QMenuBar	*bar;
#endif
	Poller		*poller;
	QTranslator	*appTranslator, *commonTranslator, *qtTranslator;
};

Application::Application( int &argc, char **argv )
:	QtSingleApplication( argc, argv )
,	d( new ApplicationPrivate )
{
	QStringList args = arguments();
	args.removeFirst();
	if( isRunning() )
	{
		sendMessage( args.join( "\", \"" ) );
		return;
	}

	connect( this, SIGNAL(messageReceived(QString)), SLOT(parseArgs(QString)) );

#ifdef Q_OS_LINUX
	QFile::setEncodingFunction( fileEncoder );
	QFile::setDecodingFunction( fileDecoder );
#endif

	setApplicationName( APP );
	setApplicationVersion( VER_STR( FILE_VER_DOT ) );
	setOrganizationDomain( DOMAINURL );
	setOrganizationName( ORG );
	setStyleSheet(
		"QDialogButtonBox { dialogbuttonbox-buttons-have-icons: 0; }\n"
		"* { font: 12px \"Arial, Liberation Sans\"; }"
	);
	QPalette p = palette();
	p.setBrush( QPalette::Link, QBrush( "#E99401" ) );
	p.setBrush( QPalette::LinkVisited, QBrush( "#E99401" ) );
	setPalette( p );
	setWindowIcon( QIcon( ":/images/crypto_128x128.png" ) );

	qRegisterMetaType<QSslCertificate>("QSslCertificate");
	qRegisterMetaType<TokenData>("TokenData");

	new Common( this );

	// Actions
	d->closeAction = new QAction( this );
	d->closeAction->setShortcut( Qt::CTRL + Qt::Key_W );
	connect( d->closeAction, SIGNAL(triggered()), SLOT(closeWindow()) );

#ifdef Q_OS_MAC
	setQuitOnLastWindowClosed( false );

	d->aboutAction = new QAction( this );
	d->aboutAction->setMenuRole( QAction::AboutRole );
	connect( d->aboutAction, SIGNAL(triggered()), SLOT(showAbout()) );

	d->settingsAction = new QAction( this );
	d->settingsAction->setMenuRole( QAction::PreferencesRole );
	connect( d->settingsAction, SIGNAL(triggered()), SLOT(showSettings()) );

	d->newWindowAction = new QAction( this );
	connect( d->newWindowAction, SIGNAL(triggered()), SLOT(parseArgs()) );

	d->bar = new QMenuBar;
	QMenu *macmenu = new QMenu( d->bar );
	macmenu->addAction( d->settingsAction );
	macmenu->addAction( d->aboutAction );
	d->bar->addMenu( macmenu );
	d->menu = new QMenu();
	d->menu->addAction( d->newWindowAction );
	d->menu->addAction( d->closeAction );
	d->bar->addMenu( d->menu );
	qt_mac_set_dock_menu( d->menu );
#endif

	initDigiDocLib();
	QString ini = QString( "%1/digidoc.ini" ).arg( applicationDirPath() );
	if( QFileInfo( ini ).isFile() )
		initConfigStore( ini.toUtf8() );
	else
		initConfigStore( NULL );

	installTranslator( d->appTranslator = new QTranslator( this ) );
	installTranslator( d->commonTranslator = new QTranslator( this ) );
	installTranslator( d->qtTranslator = new QTranslator( this ) );

	d->poller = new Poller();
	connect( d->poller, SIGNAL(dataChanged(TokenData)), SLOT(dataChanged(TokenData)) );
	connect( d->poller, SIGNAL(error(QString,quint8)), SLOT(showWarning(QString,quint8)) );
	d->data.setCard( "loading" );
	d->poller->start();

	parseArgs( args.join( "\", \"" ) );
}

Application::~Application()
{
	if( !isRunning() )
	{
#ifdef Q_OS_MAC
		delete d->bar;
#endif
		delete d->poller;
		cleanupConfigStore( NULL );
		finalizeDigiDocLib();
	}
	delete d;
}

void Application::closeWindow()
{
	if( MainWindow *w = qobject_cast<MainWindow*>(activeWindow()) )
		w->closeDoc();
	else if( QDialog *d = qobject_cast<QDialog*>(activeWindow()) )
		d->reject();
	else if( QWidget *w = qobject_cast<QWidget*>(activeWindow()) )
		w->deleteLater();
}

void Application::dataChanged( const TokenData &data ) { d->data = data; }

bool Application::event( QEvent *e )
{
	switch( e->type() )
	{
#ifdef Q_OS_MAC
	case REOpenEvent::Type:
		if( !activeWindow() )
			parseArgs();
		return true;
#endif
	case QEvent::FileOpen:
	{
		parseArgs( static_cast<QFileOpenEvent*>(e)->file() );
		return true;
	}
	default: return QApplication::event( e );
	}
}

void Application::loadTranslation( const QString &lang )
{
	d->appTranslator->load( ":/translations/" + lang );
	d->commonTranslator->load( ":/translations/common_" + lang );
	d->qtTranslator->load( ":/translations/qt_" + lang );
	d->closeAction->setText( tr("Close") );
#ifdef Q_OS_MAC
	d->aboutAction->setText( tr("About") );
	d->newWindowAction->setText( tr("New Window") );
	d->settingsAction->setText( tr("Settings") );
	d->menu->setTitle( tr("&File") );
#endif
}

void Application::parseArgs( const QString &msg )
{
	QStringList params = msg.split( "\", \"", QString::SkipEmptyParts );
	MainWindow *w = new MainWindow( params );
	w->addAction( d->closeAction );
	w->show();
}

Poller* Application::poller() const { return d->poller; }

void Application::showAbout()
{
	AboutWidget *a = new AboutWidget( activeWindow() );
	a->addAction( d->closeAction );
	a->show();
}

void Application::showSettings()
{
	SettingsDialog *s = new SettingsDialog( activeWindow() );
	s->addAction( d->closeAction );
	s->show();
}

void Application::showWarning( const QString &msg, quint8 code )
{
	switch( code )
	{
	case Poller::PinCanceled: return;
	default: break;
	}

	QMessageBox d( QMessageBox::Warning, tr("DigiDoc crypto"), msg, QMessageBox::Close | QMessageBox::Help, activeWindow() );
	if( d.exec() == QMessageBox::Help )
		Common::showHelp( msg );
}

TokenData Application::tokenData() const { return d->data; }
