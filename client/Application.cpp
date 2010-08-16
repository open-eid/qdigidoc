/*
 * QDigiDocClient
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

#include "DigiDoc.h"
#include "MainWindow.h"
#include "QSigner.h"
#include "RegisterP12.h"
#include "SettingsDialog.h"
#include "version.h"

#include "common/Common.h"
#include "common/TokenData.h"

#include <digidocpp/ADoc.h>
#include <digidocpp/Conf.h>
#include <digidocpp/crypto/cert/DirectoryX509CertStore.h>

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
	ApplicationPrivate(): signer(0) {}

	TokenData	data;
	QAction		*closeAction, *settingsAction;
#ifdef Q_OS_MAC
	QMenu		*menu;
	QMenuBar	*bar;
#endif
	QSigner		*signer;
	QTranslator *appTranslator, *commonTranslator, *qtTranslator;
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
	setWindowIcon( QIcon( ":/images/digidoc_icon_48x48.png" ) );

	qRegisterMetaType<QSslCertificate>("QSslCertificate");
	qRegisterMetaType<TokenData>("TokenData");

	Common *common = new Common( this );
	QDesktopServices::setUrlHandler( "browse", common, "browse" );
	QDesktopServices::setUrlHandler( "mailto", common, "mailTo" );

	// Actions
	d->closeAction = new QAction( this );
	d->closeAction->setShortcut( Qt::CTRL + Qt::Key_W );
	connect( d->closeAction, SIGNAL(triggered()), SLOT(closeWindow()) );

#ifdef Q_OS_MAC
	setQuitOnLastWindowClosed( false );
	d->settingsAction = new QAction( this );
	d->settingsAction->setMenuRole( QAction::PreferencesRole );
	connect( d->settingsAction, SIGNAL(triggered()), SLOT(showSettings()) );

	d->bar = new QMenuBar;
	d->menu = new QMenu( d->bar );
	d->menu->addAction( d->settingsAction );
	d->menu->addAction( d->closeAction );
	d->bar->addMenu( d->menu );
#endif

	try
	{
		digidoc::initialize();
		digidoc::X509CertStore::init( new digidoc::DirectoryX509CertStore() );
	}
	catch( const digidoc::Exception &e )
	{
		QStringList causes;
		digidoc::Exception::ExceptionCode code;
		DigiDoc::parseException( e, causes, code );
		showWarning( tr("Failed to initalize.<br />%1").arg( causes.join("\n") ) );
		return;
	}

	installTranslator( d->appTranslator = new QTranslator( this ) );
	installTranslator( d->commonTranslator = new QTranslator( this ) );
	installTranslator( d->qtTranslator = new QTranslator( this ) );

	d->signer = new QSigner();
	connect( d->signer, SIGNAL(dataChanged(TokenData)), SLOT(dataChanged(TokenData)) );
	connect( d->signer, SIGNAL(error(QString)), SLOT(showWarning(QString)) );
	d->signer->start();

	parseArgs( args.join( "\", \"" ) );
}

Application::~Application()
{
	if( !isRunning() )
	{
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
	if( MainWindow *w = qobject_cast<MainWindow*>(activeWindow()) )
		w->closeDoc();
	else if( QDialog *d = qobject_cast<QDialog*>(activeWindow()) )
		d->reject();
	else if( QWidget *w = qobject_cast<QDialog*>(activeWindow()) )
		w->deleteLater();
}

QString Application::confValue( ConfParameter parameter, const QVariant &value )
{
	digidoc::Conf *i = NULL;
	try { i = digidoc::Conf::getInstance(); }
	catch( const digidoc::Exception & ) { return value.toString(); }

	std::string r;
	switch( parameter )
	{
	case PKCS11Module: r = i->getPKCS11DriverPath(); break;
	case ProxyHost: r = i->getProxyHost(); break;
	case ProxyPort: r = i->getProxyPort(); break;
	case ProxyUser: r = i->getProxyUser(); break;
	case ProxyPass: r = i->getProxyPass(); break;
	case PKCS12Cert: r = i->getPKCS12Cert(); break;
	case PKCS12Pass: r = i->getPKCS12Pass(); break;
	default: break;
	}
	return r.empty() ? value.toString() : QString::fromStdString( r );
}

void Application::dataChanged( const TokenData &data )
{
	bool changed = d->data != data;
	d->data = data;
	if( changed ) Q_EMIT dataChanged();
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
	QStringList exts = QStringList() << "p12" << "p12d";
	if( exts.contains( QFileInfo( params.value( 0 ) ).suffix(), Qt::CaseInsensitive ) )
	{
		RegisterP12 *s = new RegisterP12( params[0] );
		s->addAction( d->closeAction );
		s->show();
	}
	else
	{
		MainWindow *w = new MainWindow( params );
		w->addAction( d->closeAction );
		w->show();
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
	default: break;
	}
}

void Application::showSettings( int page )
{
	SettingsDialog s( activeWindow() );
	s.addAction( d->closeAction );
	s.setPage( page );
	s.exec();
}

void Application::showWarning( const QString &msg )
{
	QMessageBox d( QMessageBox::Warning, tr("DigiDoc3 client"), msg, QMessageBox::Close | QMessageBox::Help, activeWindow() );
	if( d.exec() == QMessageBox::Help )
		Common::showHelp( msg );
}

QSigner* Application::signer() const { return d->signer; }

TokenData Application::tokenData() const { return d->data; }
