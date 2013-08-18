/*
 * QDigiDocClient
 *
 * Copyright (C) 2010-2013 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2010-2013 Raul Metsma <raul@innovaatik.ee>
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

#define NOMINMAX

#include "Application.h"

#include "DigiDoc.h"
#include "MainWindow.h"
#include "QSigner.h"
#include "RegisterP12.h"
#include "SettingsDialog.h"

#include "crypto/MainWindow.h"
#include "crypto/Poller.h"

#include <common/AboutDialog.h>
#include <common/Settings.h>

#include <digidocpp/Container.h>
#include <digidocpp/XmlConf.h>

#include <libdigidoc/DigiDocConfig.h>

#include "qtsingleapplication/src/qtlocalpeer.h"

#include <QtCore/QFileInfo>
#include <QtCore/QSysInfo>
#include <QtCore/QTranslator>
#include <QtCore/QUrl>
#include <QtGui/QDesktopServices>
#if QT_VERSION >= 0x050000
#include <QtWidgets/QMessageBox>
#else
#include <QtGui/QMessageBox>
#endif
#include <QtGui/QFileOpenEvent>
#include <QtNetwork/QSslCertificate>
#include <QtNetwork/QSslConfiguration>

#if defined(Q_OS_MAC)
#include <common/MacMenuBar.h>

class DigidocConf: public digidoc::XmlConf
{
public:
	DigidocConf(): digidoc::XmlConf() { s.beginGroup( "Client" ); }

	std::string proxyHost() const
	{ return s.value( "ProxyHost" ).toString().toStdString(); }
	std::string proxyPort() const
	{ return s.value( "ProxyPort" ).toString().toStdString(); }
	std::string proxyUser() const
	{ return s.value( "ProxyUser" ).toString().toStdString(); }
	std::string proxyPass() const
	{ return s.value( "ProxyPass" ).toString().toStdString(); }
	std::string PKCS12Cert() const
	{ return ""; }
	std::string PKCS12Pass() const
	{ return ""; }
	bool PKCS12Disable() const
	{ return s.value( "PKCS12Disable", false ).toBool(); }
	std::string PKCS11Driver() const
	{ return QString( qApp->applicationDirPath() + "/opensc-pkcs11.so" ).toStdString(); }


	void setProxyHost( const std::string &host )
	{ s.setValue( "ProxyHost", QString::fromStdString( host ) ); }
	void setProxyPort( const std::string &port )
	{ s.setValue( "ProxyPort", QString::fromStdString( port ) ); }
	void setProxyUser( const std::string &user )
	{ s.setValue( "ProxyUser", QString::fromStdString( user ) ); }
	void setProxyPass( const std::string &pass )
	{ s.setValue( "ProxyPass", QString::fromStdString( pass ) ); }
	void setPKCS12Cert( const std::string & ) {}
	void setPKCS12Pass( const std::string & ) {}
	void setPKCS12Disable( bool disable )
	{ s.setValue( "PKCS12Disable", disable ); }

private:
	Settings s;
};
#endif

class ApplicationPrivate
{
public:
	ApplicationPrivate(): poller(0), signer(0) {}

	QAction		*closeAction, *newAction;
#ifdef Q_OS_MAC
	MacMenuBar	*bar;
#endif
	Poller		*poller;
	QSigner		*signer;
	QTranslator	*appTranslator, *commonTranslator, *cryptoTranslator, *qtTranslator;
	QString		lang;
};

Application::Application( int &argc, char **argv )
:	Common( argc, argv )
,	d( new ApplicationPrivate )
{
	QStringList args = arguments();
	args.removeFirst();
#ifndef Q_OS_MAC
	if( isRunning() )
	{
		sendMessage( args.join( "\", \"" ) );
		return;
	}
	connect( this, SIGNAL(messageReceived(QString)), SLOT(parseArgs(QString)) );
#endif

	setApplicationName( APP );
	setApplicationVersion( QString( "%1.%2.%3.%4" )
		.arg( MAJOR_VER ).arg( MINOR_VER ).arg( RELEASE_VER ).arg( BUILD_VER ) );
	setOrganizationDomain( DOMAINURL );
	setOrganizationName( ORG );
	setWindowIcon( QIcon( ":/images/digidoc_icon_128x128.png" ) );
	detectPlugins();

	// Actions
	d->closeAction = new QAction( this );
	d->closeAction->setShortcut( Qt::CTRL + Qt::Key_W );
	connect( d->closeAction, SIGNAL(triggered()), SLOT(closeWindow()) );

	d->newAction = new QAction( this );
	d->newAction->setShortcut( Qt::CTRL + Qt::Key_N );
	connect( d->newAction, SIGNAL(triggered()), SLOT(parseArgs()) );

#if defined(Q_OS_MAC)
	setQuitOnLastWindowClosed( false );

	d->bar = new MacMenuBar;
	d->bar->addAction( MacMenuBar::AboutAction, this, SLOT(showAbout()) );
	d->bar->addAction( MacMenuBar::PreferencesAction, this, SLOT(showSettings()) );
	d->bar->fileMenu()->addAction( d->newAction );
	d->bar->fileMenu()->addAction( d->closeAction );
	d->bar->dockMenu()->addAction( d->newAction );
#endif

	installTranslator( d->appTranslator = new QTranslator( this ) );
	installTranslator( d->commonTranslator = new QTranslator( this ) );
	installTranslator( d->cryptoTranslator = new QTranslator( this ) );
	installTranslator( d->qtTranslator = new QTranslator( this ) );
	loadTranslation( Settings::language() );

	try
	{
		digidoc::initialize( QString( "%1/%2 (%3)" )
			.arg( applicationName(), applicationVersion(), applicationOs() ).toUtf8().constData() );
#ifdef Q_OS_MAC
		digidoc::Conf::init( new DigidocConf );
#endif
	}
	catch( const digidoc::Exception &e )
	{
		QStringList causes;
		digidoc::Exception::ExceptionCode code = digidoc::Exception::NoException;
		int ddocError = -1;
		DigiDoc::parseException( e, causes, code, ddocError );
		showWarning( tr("Failed to initalize."), ddocError, causes.join("\n") );
	}

	initDigiDocLib();
	QString ini = QString( "%1/digidoc.ini" ).arg( applicationDirPath() );
	if( QFileInfo( ini ).isFile() )
		initConfigStore( ini.toUtf8() );
	else
		initConfigStore( NULL );

	QSigner::ApiType api = QSigner::PKCS11;
#ifdef Q_OS_WIN
	QString provider;
	QSettings reg( "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards", QSettings::NativeFormat );
	Q_FOREACH( const QString &group, reg.childGroups() )
	{
		if( group.contains( "esteid", Qt::CaseInsensitive ) )
		{
			provider = reg.value( group + "/" + "Crypto Provider" ).toString();
			break;
		}
	}
	if( QSysInfo::windowsVersion() >= QSysInfo::WV_VISTA && provider != "EstEID Card CSP" )
		api = QSigner::CNG;
	if( args.contains("-capi") && QSysInfo::windowsVersion() >= QSysInfo::WV_VISTA )
		showWarning( tr("CAPI parameter is not supported on Windows Vista and newer") );
	else if( args.contains("-capi") )
		api = QSigner::CAPI;
	if( args.contains("-cng") && QSysInfo::windowsVersion() < QSysInfo::WV_VISTA )
		showWarning( tr("CNG parameter is not supported on Windows XP") );
	else if( args.contains("-cng") )
		api = QSigner::CNG;
#endif
	if( args.contains("-pkcs11") ) api = QSigner::PKCS11;
	d->poller = new Poller( Poller::ApiType(api), this );
	d->signer = new QSigner( api, this );
	parseArgs( args );
}

Application::~Application()
{
#ifndef Q_OS_MAC
	if( !isRunning() )
	{
		if( QtLocalPeer *obj = findChild<QtLocalPeer*>() )
			delete obj;
		digidoc::terminate();
		cleanupConfigStore( 0 );
		finalizeDigiDocLib();
	}
#else
	delete d->bar;
	digidoc::terminate();
	cleanupConfigStore( 0 );
	finalizeDigiDocLib();
#endif
	delete d;
}

void Application::activate( QWidget *w )
{
#ifdef Q_OS_MAC
	w->installEventFilter( d->bar );
#endif
	w->addAction( d->closeAction );
	w->activateWindow();
	w->show();
	w->raise();
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

QVariant Application::confValue( ConfParameter parameter, const QVariant &value )
{
	digidoc::Conf *i = 0;
	try { i = digidoc::Conf::instance(); }
	catch( const digidoc::Exception & ) { return value; }

	QByteArray r;
	switch( parameter )
	{
	case PKCS11Module: r = i->PKCS11Driver().c_str(); break;
	case ProxyHost: r = i->proxyHost().c_str(); break;
	case ProxyPort: r = i->proxyPort().c_str(); break;
	case ProxyUser: r = i->proxyUser().c_str(); break;
	case ProxyPass: r = i->proxyPass().c_str(); break;
	case PKCS12Cert: r = i->PKCS12Cert().c_str(); break;
	case PKCS12Pass: r = i->PKCS12Pass().c_str(); break;
	case PKCS12Disable: return i->PKCS12Disable(); break;
	default: break;
	}
	return r.isEmpty() ? value.toString() : QString::fromUtf8( r );
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
		parseArgs( QStringList() << static_cast<QFileOpenEvent*>(e)->file() );
		return true;
	default: return Common::event( e );
	}
}

QString Application::lastPath() const
{ return Settings().value( "Client/lastPath" ).toString(); }

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
	d->cryptoTranslator->load( ":/translations/crypto_" + lang );
	d->qtTranslator->load( ":/translations/qt_" + lang );
	d->closeAction->setText( tr("Close window") );
	d->newAction->setText( tr("New window") );
}

bool Application::notify( QObject *o, QEvent *e )
{
	try
	{
		return QApplication::notify( o, e );
	}
	catch( const digidoc::Exception &e )
	{
		QStringList causes;
		digidoc::Exception::ExceptionCode code = digidoc::Exception::NoException;
		int ddocError = -1;
		DigiDoc::parseException( e, causes, code, ddocError );
		showWarning( tr("Caught exception!"), ddocError, causes.join("\n") );
	}
	catch(...)
	{
		showWarning( tr("Caught exception!") );
	}

	return false;
}

void Application::parseArgs( const QString &msg )
{
	QStringList params;
	Q_FOREACH( const QString &param, msg.split( "\", \"", QString::SkipEmptyParts ) )
	{
#if QT_VERSION >= 0x050000
		QUrl url( param, QUrl::StrictMode );
#else
		QUrl url( param );
#endif
		params << (url.errorString().isEmpty() ? url.toLocalFile() : param);
	}
	parseArgs( params );
}

void Application::parseArgs( const QStringList &args )
{
	bool crypto = args.contains("-crypto");
	QStringList params = args;
	params.removeAll("-crypto");
	params.removeAll("-capi");
	params.removeAll("-cng");
	params.removeAll("-pkcs11");
	params.removeAll("-noNativeFileDialog");

	QString suffix = QFileInfo( params.value( 0 ) ).suffix();
	if( (QStringList() << "p12" << "p12d").contains( suffix, Qt::CaseInsensitive ) )
		activate( new RegisterP12( params[0] ) );
	else if( crypto || (QStringList() << "cdoc").contains( suffix, Qt::CaseInsensitive ) )
		showCrypto( params );
	else
		showClient( params );
}

Poller* Application::poller() const { return d->poller; }

int Application::run()
{
#ifndef Q_OS_MAC
	if( isRunning() ) return 0;
#endif
	return exec();
}

void Application::setConfValue( ConfParameter parameter, const QVariant &value )
{
	try
	{
		digidoc::XmlConf *i = static_cast<digidoc::XmlConf*>(digidoc::Conf::instance());
		if(!i)
			return;
		QByteArray v = value.toString().toUtf8();
		switch( parameter )
		{
		case ProxyHost: i->setProxyHost( v.constData() ); break;
		case ProxyPort: i->setProxyPort( v.constData() ); break;
		case ProxyUser: i->setProxyUser( v.constData() ); break;
		case ProxyPass: i->setProxyPass( v.constData() ); break;
		case PKCS12Cert: i->setPKCS12Cert( v.constData() ); break;
		case PKCS12Pass: i->setPKCS12Pass( v.constData() ); break;
		case PKCS12Disable: i->setPKCS12Disable( value.toBool() ); break;
		default: break;
		}
	}
	catch( const digidoc::Exception &e )
	{
		QStringList causes;
		digidoc::Exception::ExceptionCode code = digidoc::Exception::NoException;
		int ddocError = -1;
		DigiDoc::parseException( e, causes, code, ddocError );
		showWarning( tr("Caught exception!"), ddocError, causes.join("\n") );
	}
}

void Application::setLastPath( const QString &path )
{ Settings().setValue( "Client/lastPath", path ); }

void Application::showAbout()
{
	AboutDialog *a = new AboutDialog( activeWindow() );
	a->addAction( d->closeAction );
	a->open();
}

void Application::showClient( const QStringList &params )
{
	QWidget *w = 0;
	foreach( QWidget *m, qApp->topLevelWidgets() )
	{
		MainWindow *main = qobject_cast<MainWindow*>(m);
		if( main && main->windowFilePath().isEmpty() )
		{
			w = main;
			break;
		}
	}
	if( !w )
		w = new MainWindow();
	if( !params.isEmpty() )
		QMetaObject::invokeMethod( w, "open", Q_ARG(QStringList,params) );
	activate( w );
}

void Application::showCrypto( const QStringList &params )
{
	QWidget *w = 0;
	foreach( QWidget *m, qApp->topLevelWidgets() )
	{
		Crypto::MainWindow *main = qobject_cast<Crypto::MainWindow*>(m);
		if( main && main->windowFilePath().isEmpty() )
		{
			w = main;
			break;
		}
	}
	if( !w )
		w = new Crypto::MainWindow();
	if( !params.isEmpty() )
		QMetaObject::invokeMethod( w, "open", Q_ARG(QStringList,params) );
	activate( w );
}

void Application::showSettings( int page )
{
	SettingsDialog *s = new SettingsDialog( activeWindow() );
	s->addAction( d->closeAction );
	s->setPage( page );
	s->open();
}

void Application::showWarning( const QString &msg )
{
    showWarning( msg, -1 );
}

void Application::showWarning( const QString &msg, int err, const QString &details, const QString &search )
{
	QMessageBox d( QMessageBox::Warning, tr("DigiDoc3 client"), msg, QMessageBox::Close, activeWindow() );
	d.setWindowModality( Qt::WindowModal );
	if( !details.isEmpty() )
	{
		d.addButton( QMessageBox::Help );
		d.setDetailedText( details );
	}
	if( d.exec() == QMessageBox::Help )
		Common::showHelp( search.isEmpty() ? msg : search, err );
}

QSigner* Application::signer() const { return d->signer; }
