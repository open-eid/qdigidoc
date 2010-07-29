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

#include "Application.h"

#include "MainWindow.h"
#include "Poller.h"
#include "SettingsDialog.h"
#include "version.h"

#include "common/Common.h"

#include <libdigidoc/DigiDocConfig.h>

#include <QDesktopServices>
#ifdef Q_OS_LINUX
#include <QFile>
#endif
#include <QFileInfo>
#include <QFileOpenEvent>
#ifdef Q_OS_MAC
#include <QMenu>
#include <QMenuBar>
#endif
#include <QMessageBox>
#include <QPalette>
#include <QSslCertificate>
#include <QTranslator>

class ApplicationPrivate
{
public:
	ApplicationPrivate(): poller( 0 ) {}

	QSslCertificate	authCert;
	QStringList		cards;
	QString			card;
	QAction			*closeAction, *settingsAction;
	QMenu			*menu;
	QTranslator		*appTranslator, *commonTranslator, *qtTranslator;
	Poller			*poller;
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

	qRegisterMetaType<QSslCertificate>("QSslCertificate");

	Common *common = new Common( this );
	QDesktopServices::setUrlHandler( "browse", common, "browse" );
	QDesktopServices::setUrlHandler( "mailto", common, "mailTo" );

	// Actions
	d->closeAction = new QAction( this );
	d->closeAction->setShortcut( Qt::CTRL + Qt::Key_W );
	connect( d->closeAction, SIGNAL(triggered()), SLOT(closeWindow()) );

#ifdef Q_OS_MAC
	d->settingsAction = new QAction( this );
	d->settingsAction->setMenuRole( QAction::PreferencesRole );
	connect( d->settingsAction, SIGNAL(triggered()), SLOT(showSettings()) );

	QMenuBar *bar = new QMenuBar;
	QMenu *menu = new QMenu( bar );
	menu->addAction( d->settingsAction );
	menu->addAction( d->closeAction );
	bar->addMenu( menu );
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
	connect( d->poller, SIGNAL(dataChanged(QStringList,QString,QSslCertificate)),
		SLOT(dataChanged(QStringList,QString,QSslCertificate)) );
	connect( d->poller, SIGNAL(error(QString)), SLOT(showWarning(QString)) );
	d->poller->start();

	parseArgs( args.join( "\", \"" ) );
}

Application::~Application()
{
	if( !isRunning() )
	{
		delete d->poller;
		cleanupConfigStore( NULL );
		finalizeDigiDocLib();
	}
	delete d;
}

QString Application::activeCard() const { return d->card; }
QSslCertificate Application::authCert() const { return d->authCert; }


void Application::closeWindow()
{
	if( MainWindow *w = qobject_cast<MainWindow*>(activeWindow()) )
		w->closeDoc();
	else if( QDialog *d = qobject_cast<QDialog*>(activeWindow()) )
		d->reject();
	else if( QWidget *w = qobject_cast<QDialog*>(activeWindow()) )
		w->deleteLater();
}

void Application::dataChanged( const QStringList &cards, const QString &card,
	const QSslCertificate &auth )
{
	bool changed = false;
	changed = qMax( changed, d->cards != cards );
	changed = qMax( changed, d->card != card );
	changed = qMax( changed, d->authCert != auth );
	d->cards = cards;
	d->card = card;
	d->authCert = auth;
	if( changed )
		Q_EMIT dataChanged();
}

bool Application::event( QEvent *e )
{
	switch( e->type() )
	{
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
QStringList Application::presentCards() const { return d->cards; }

void Application::showSettings()
{
	SettingsDialog s( activeWindow() );
	s.addAction( d->closeAction );
	s.exec();
}

void Application::showWarning( const QString &msg )
{
	QMessageBox d( QMessageBox::Warning, tr("DigiDoc3 crypto"), msg, QMessageBox::Close | QMessageBox::Help, activeWindow() );
	if( d.exec() == QMessageBox::Help )
		Common::showHelp( msg );
}
