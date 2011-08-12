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
#include <QUrl>

#if defined(Q_OS_MAC)
#include <QMenu>
#include <QMenuBar>

void qt_mac_set_dock_menu( QMenu *menu );
#endif

class ApplicationPrivate
{
public:
	ApplicationPrivate():
#ifdef Q_OS_MAC
		dockSeparator(0),
#endif
		poller(0) {}

	QAction		*closeAction, *newAction;
#ifdef Q_OS_MAC
	QAction		*aboutAction, *settingsAction, *dockSeparator;
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
	d->dock->addAction( d->newAction );
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

	d->poller = new Poller( args.contains("-capi"), this );
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
		w->close();
}

bool Application::event( QEvent *e )
{
	switch( int(e->type()) )
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
#ifdef Q_OS_MAC
	switch( e->type() )
	{
	case QEvent::Close:
	case QEvent::Destroy:
		Q_FOREACH( QAction *a, d->windowGroup->actions() )
			if( o == a->data().value<QWidget*>() )
				delete a;
		if( d->windowGroup->actions().isEmpty() && d->dockSeparator )
		{
			d->dockSeparator->deleteLater();
			d->dockSeparator = 0;
		}
		return Common::eventFilter( o, e );
	case QEvent::WindowActivate:
		Q_FOREACH( QAction *a, d->windowGroup->actions() )
			a->setChecked( o == a->data().value<QWidget*>() );
		if( !d->windowGroup->checkedAction() )
		{
			QAction *a = new QAction( o->property( "windowTitle" ).toString(), d->dock );
			a->setCheckable( true );
			a->setData( QVariant::fromValue( qobject_cast<QWidget*>(o) ) );
			a->setActionGroup( d->windowGroup );

			if( !d->dockSeparator )
				d->dockSeparator = d->dock->insertSeparator( d->newAction );
			d->dock->insertAction( d->dockSeparator, a );
		}
		return true;
	case QEvent::WindowTitleChange:
		Q_FOREACH( QAction *a, d->windowGroup->actions() )
			if( o == a->data().value<QWidget*>() )
				a->setText( o->property( "windowTitle" ).toString() );
		return true;
	default: break;
	}
#endif
	return Common::eventFilter( o, e );
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
	QStringList params;
	Q_FOREACH( const QString &param, msg.split( "\", \"", QString::SkipEmptyParts ) )
	{
		QUrl url( param );
		params << (url.errorString().isEmpty() ? url.toLocalFile() : param);
	}
	params.removeAll("-capi");

	QWidget *w = new MainWindow();
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
