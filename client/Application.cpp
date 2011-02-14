/*
 * QDigiDocClient
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

#include "DigiDoc.h"
#include "MainWindow.h"
#include "QSigner.h"
#include "RegisterP12.h"
#include "SettingsDialog.h"
#include "version.h"

#include <common/AboutWidget.h>
#include <common/Common.h>
#include <common/MessageBox.h>
#include <common/Settings.h>
#include <common/TokenData.h>

#include <digidocpp/ADoc.h>
#include <digidocpp/Conf.h>
#include <digidocpp/crypto/cert/DirectoryX509CertStore.h>

#include "qtsingleapplication/src/qtlocalpeer.h"

#include <QDesktopServices>
#include <QFileInfo>
#include <QFileOpenEvent>
#include <QPalette>
#include <QSslCertificate>
#include <QSslConfiguration>
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
	ApplicationPrivate(): signer(0) {}

	QAction		*closeAction;
#ifdef Q_OS_MAC
	QAction		*aboutAction, *newWindowAction, *settingsAction;
	QMenu		*menu;
	QMenuBar	*bar;
#endif
	QSigner		*signer;
	QTranslator	*appTranslator, *commonTranslator, *qtTranslator;
	QString		lang;
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

	qputenv( "LANG", "en_US.UTF-8" );
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
	p.setBrush( QPalette::Link, QBrush( "#509B00" ) );
	p.setBrush( QPalette::LinkVisited, QBrush( "#509B00" ) );
	setPalette( p );
	setWindowIcon( QIcon( ":/images/digidoc_icon_128x128.png" ) );

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

	installTranslator( d->appTranslator = new QTranslator( this ) );
	installTranslator( d->commonTranslator = new QTranslator( this ) );
	installTranslator( d->qtTranslator = new QTranslator( this ) );
	loadTranslation( Settings::language() );

	try
	{
		digidoc::initialize();
		digidoc::X509CertStore::init( new digidoc::DirectoryX509CertStore() );
		QSslConfiguration c = QSslConfiguration::defaultConfiguration();
		c.setCaCertificates( c.caCertificates() + QSslCertificate::fromPath(
			QString( "%1/*" ).arg( confValue( CertStorePath ).toString() ), QSsl::Pem, QRegExp::Wildcard ) );
		QSslConfiguration::setDefaultConfiguration( c );
	}
	catch( const digidoc::Exception &e )
	{
		QStringList causes;
		digidoc::Exception::ExceptionCode code = digidoc::Exception::NoException;
		int ddocError = -1;
		DigiDoc::parseException( e, causes, code, ddocError );
		showWarning( tr("Failed to initalize."), ddocError, causes.join("\n") );
	}

	d->signer = new QSigner();
	connect( d->signer, SIGNAL(error(QString)), SLOT(showWarning(QString)) );
	d->signer->start();

	parseArgs( args.join( "\", \"" ) );
}

Application::~Application()
{
	if( !isRunning() )
	{
		QtLocalPeer *obj = findChild<QtLocalPeer*>();
		if( obj )
			delete obj;
#ifdef Q_OS_MAC
		delete d->bar;
#endif
		delete d->signer;
		digidoc::X509CertStore::destroy();
		digidoc::terminate();
	}
	delete d;
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

QVariant Application::confValue( ConfParameter parameter, const QVariant &value )
{
	digidoc::Conf *i = 0;
	try { i = digidoc::Conf::getInstance(); }
	catch( const digidoc::Exception & ) { return value; }

	std::string r;
	switch( parameter )
	{
	case CertStorePath: r = i->getCertStorePath(); break;
	case PKCS11Module: r = i->getPKCS11DriverPath(); break;
	case ProxyHost: r = i->getProxyHost(); break;
	case ProxyPort: r = i->getProxyPort(); break;
	case ProxyUser: r = i->getProxyUser(); break;
	case ProxyPass: r = i->getProxyPass(); break;
	case PKCS12Cert: r = i->getPKCS12Cert(); break;
	case PKCS12Pass: r = i->getPKCS12Pass(); break;
	case PKCS12Disable: return i->getPKCS12Disable(); break;
	default: break;
	}
	return r.empty() ? value.toString() : QString::fromStdString( r );
}

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
	if( d->lang == lang )
		return;
	Settings().setValue( "Main/Language", d->lang = lang );

	if( lang == "en" ) QLocale::setDefault( QLocale( QLocale::English, QLocale::UnitedKingdom ) );
	else if( lang == "ru" ) QLocale::setDefault( QLocale( QLocale::Russian, QLocale::RussianFederation ) );
	else QLocale::setDefault( QLocale( QLocale::Estonian, QLocale::Estonia ) );

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
	QStringList exts = QStringList() << "p12" << "p12d";
	if( exts.contains( QFileInfo( params.value( 0 ) ).suffix(), Qt::CaseInsensitive ) )
	{
		RegisterP12 *s = new RegisterP12( params[0] );
		s->addAction( d->closeAction );
		s->show();
	}
	else
	{
		MainWindow *w = new MainWindow();
		w->addAction( d->closeAction );
		w->show();
		if( !params.isEmpty() )
			QMetaObject::invokeMethod( w, "open", Q_ARG(QStringList,params) );
	}
}

void Application::setConfValue( ConfParameter parameter, const QVariant &value )
{
	digidoc::Conf *i = NULL;
	try { i = digidoc::Conf::getInstance(); }
	catch( const digidoc::Exception & ) { return; }

	const std::string v = value.toString().toStdString();
	switch( parameter )
	{
	case ProxyHost: i->setProxyHost( v ); break;
	case ProxyPort: i->setProxyPort( v ); break;
	case ProxyUser: i->setProxyUser( v ); break;
	case ProxyPass: i->setProxyPass( v ); break;
	case PKCS12Cert: i->setPKCS12Cert( v ); break;
	case PKCS12Pass: i->setPKCS12Pass( v ); break;
	case PKCS12Disable: i->setPKCS12Disable( value.toBool() ); break;
	default: break;
	}
}

void Application::showAbout()
{
	AboutWidget *a = new AboutWidget( activeWindow() );
	a->addAction( d->closeAction );
	a->show();
}

void Application::showSettings( int page )
{
	SettingsDialog *s = new SettingsDialog( activeWindow() );
	s->addAction( d->closeAction );
	s->setPage( page );
	s->show();
}

void Application::showWarning( const QString &msg, int err, const QString &details )
{
	DMessageBox d( QMessageBox::Warning, tr("DigiDoc3 client"), msg, QMessageBox::Close, activeWindow() );
	d.setWindowModality( Qt::WindowModal );
	if( !details.isEmpty() )
	{
		d.addButton( QMessageBox::Help );
		d.setDetailedText( details );
	}
	if( d.exec() == QMessageBox::Help )
		Common::showHelp( msg, err );
}

QSigner* Application::signer() const { return d->signer; }
