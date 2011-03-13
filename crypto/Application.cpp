/*
 * QDigiDocCrypto
 *
 * Copyright (C) 2010-2011 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2010-2011 Raul Metsma <raul@innovaatik.ee>
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
#include <common/Settings.h>

#include <libdigidoc/DigiDocConfig.h>

#include "qtsingleapplication/src/qtlocalpeer.h"

#include <QDesktopServices>
#include <QFileInfo>
#include <QFileOpenEvent>
#include <QMessageBox>
#include <QTranslator>

#if defined(Q_OS_MAC)
#include <QMenu>
#include <QMenuBar>

void qt_mac_set_dock_menu( QMenu *menu );
#endif

class ApplicationPrivate
{
public:
	ApplicationPrivate(): poller(0) {}

	QAction		*closeAction, *newAction;
#ifdef Q_OS_MAC
	QAction		*aboutAction, *settingsAction;
	QActionGroup *windowGroup;
	QMenu		*menu, *dock;
	QMenuBar	*bar;
#endif
	Poller		*poller;
	QTranslator	*appTranslator, *commonTranslator, *qtTranslator;
	QString		lang;
};

Application::Application( int &argc, char **argv )
:	Common( argc, argv )
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

	setApplicationName( APP );
	setApplicationVersion( VER_STR( FILE_VER_DOT ) );
	setOrganizationDomain( DOMAINURL );
	setOrganizationName( ORG );
	setWindowIcon( QIcon( ":/images/crypto_128x128.png" ) );
	initDigiDoc();

	// Actions
	d->closeAction = new QAction( this );
	d->closeAction->setShortcut( Qt::CTRL + Qt::Key_W );
	connect( d->closeAction, SIGNAL(triggered()), SLOT(closeWindow()) );

	d->newAction = new QAction( this );
	d->newAction->setShortcut( Qt::CTRL + Qt::Key_N );
	connect( d->newAction, SIGNAL(triggered()), SLOT(parseArgs()) );

#if defined(Q_OS_MAC)
	setQuitOnLastWindowClosed( false );

	d->aboutAction = new QAction( this );
	d->aboutAction->setMenuRole( QAction::AboutRole );
	connect( d->aboutAction, SIGNAL(triggered()), SLOT(showAbout()) );

	d->settingsAction = new QAction( this );
	d->settingsAction->setMenuRole( QAction::PreferencesRole );
	connect( d->settingsAction, SIGNAL(triggered()), SLOT(showSettings()) );

	d->bar = new QMenuBar;
	d->menu = new QMenu( d->bar );
	d->menu->addAction( d->settingsAction );
	d->menu->addAction( d->aboutAction );
	d->menu->addAction( d->newAction );
	d->menu->addAction( d->closeAction );
	d->bar->addMenu( d->menu );

	d->dock = new QMenu;
	d->windowGroup = new QActionGroup( d->dock );
	connect( d->windowGroup, SIGNAL(triggered(QAction*)), SLOT(activateWindow(QAction*)) );
	qt_mac_set_dock_menu( d->dock );
#endif

	installTranslator( d->appTranslator = new QTranslator( this ) );
	installTranslator( d->commonTranslator = new QTranslator( this ) );
	installTranslator( d->qtTranslator = new QTranslator( this ) );
	loadTranslation( Settings::language() );

	initDigiDocLib();
	QString ini = QString( "%1/digidoc.ini" ).arg( applicationDirPath() );
	if( QFileInfo( ini ).isFile() )
		initConfigStore( ini.toUtf8() );
	else
		initConfigStore( NULL );

	d->poller = new Poller();
	connect( d->poller, SIGNAL(error(QString)), SLOT(showWarning(QString)) );
	d->poller->start();

	parseArgs( args.join( "\", \"" ) );
}

Application::~Application()
{
	if( !isRunning() )
	{
		if( QtLocalPeer *obj = findChild<QtLocalPeer*>() )
			delete obj;
#ifdef Q_OS_MAC
		delete d->bar;
		delete d->dock;
#endif
		delete d->poller;
		cleanupConfigStore( NULL );
		finalizeDigiDocLib();
	}
	delete d;
}

void Application::activateWindow( QAction *a )
{
	if( QWidget *w = a->data().value<QWidget*>() )
	{
		w->activateWindow();
		w->showNormal();
		w->raise();
	}
}

void Application::closeWindow()
{
#ifndef Q_OS_MAC
	if( MainWindow *w = qobject_cast<MainWindow*>(activeWindow()) )
		w->closeDoc();
	else
#endif
	if( QDialog *d = qobject_cast<QDialog*>(activeWindow()) )
		d->reject();
	else if( QWidget *w = qobject_cast<QWidget*>(activeWindow()) )
		w->deleteLater();
}

bool Application::event( QEvent *e )
{
	switch( e->type() )
	{
	case REOpenEvent::Type:
		if( !activeWindow() )
			parseArgs();
		return true;
	case QEvent::FileOpen:
		parseArgs( static_cast<QFileOpenEvent*>(e)->file() );
		return true;
	default: return Common::event( e );
	}
}

bool Application::eventFilter( QObject *o, QEvent *e )
{
	switch( e->type() )
	{
#ifdef Q_OS_MAC
	case QEvent::Close:
	case QEvent::Create:
	case QEvent::Show:
	case QEvent::WindowActivate:
	case QEvent::WindowTitleChange:
	{
		d->dock->clear();
		Q_FOREACH( QWidget *t, topLevelWidgets() )
		{
			if( !qobject_cast<MainWindow*>(t) )
				continue;
			if( e->type() == QEvent::Close && t == o )
				continue;
			QAction *a = d->dock->addAction( t->windowTitle() );
			a->setCheckable( true );
			a->setChecked( t == activeWindow() );
			a->setData( QVariant::fromValue( t ) );
			d->windowGroup->addAction( a );
		}
		if( !d->windowGroup->actions().isEmpty() )
			d->dock->addSeparator();
		d->dock->addAction( d->newAction );
		return true;
	}
#endif
	default: return QApplication::eventFilter( o, e );
	}
}

void Application::loadTranslation( const QString &lang )
{
	if( d->lang == lang )
		return;
	Settings().setValue( "Main/Language", d->lang = lang );

	if( lang == "en" ) QLocale::setDefault( QLocale( QLocale::English, QLocale::UnitedKingdom ) );
	else if( lang == "ru" ) QLocale::setDefault( QLocale( QLocale::Russian, QLocale::RussianFederation ) );
	else QLocale::setDefault( QLocale( QLocale::Estonian, QLocale::Estonia ) );

	d->appTranslator->load( ":/translations/" + lang );
	d->commonTranslator->load( ":/translations/common_" + lang );
	d->qtTranslator->load( ":/translations/qt_" + lang );
	d->closeAction->setText( tr("Close window") );
	d->newAction->setText( tr("New window") );
#ifdef Q_OS_MAC
	d->aboutAction->setText( tr("About") );
	d->settingsAction->setText( tr("Settings") );
	d->menu->setTitle( tr("&File") );
#endif
}

void Application::parseArgs( const QString &msg )
{
	QStringList params = msg.split( "\", \"", QString::SkipEmptyParts );
	MainWindow *w = new MainWindow();
	w->installEventFilter( this );
	w->addAction( d->closeAction );
	w->activateWindow();
	w->show();
	w->raise();
	if( !params.isEmpty() )
		QMetaObject::invokeMethod( w, "open", Q_ARG(QStringList,params) );
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

void Application::showWarning( const QString &msg )
{ QMessageBox( QMessageBox::Warning, tr("DigiDoc3 crypto"), msg, QMessageBox::Close, activeWindow() ).exec(); }
