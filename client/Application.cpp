/*
 * QDigiDocClient
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
#include "SettingsDialog.h"

#include "crypto/MainWindow.h"

#include <common/AboutDialog.h>
#include <common/Settings.h>
#include <common/SslCertificate.h>

#include <digidocpp/Container.h>
#include <digidocpp/XmlConf.h>
#include <digidocpp/crypto/X509Cert.h>

#include "qtsingleapplication/src/qtlocalpeer.h"

#include <QtCore/QFileInfo>
#include <QtCore/QSysInfo>
#include <QtCore/QTimer>
#include <QtCore/QTranslator>
#include <QtCore/QUrl>
#include <QtGui/QDesktopServices>
#if QT_VERSION >= 0x050000
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QProgressDialog>
#else
#include <QtGui/QMessageBox>
#endif
#include <QtGui/QFileOpenEvent>
#include <QtNetwork/QNetworkProxy>
#include <QtNetwork/QSslConfiguration>

#if defined(Q_OS_MAC)
#include <common/MacMenuBar.h>
#else
class MacMenuBar;
#endif

class DigidocConf: public digidoc::XmlConfV4
{
public:
	DigidocConf()
		: digidoc::XmlConfV4()
		, s2(qApp->applicationName())
	{
		s.beginGroup( "Client" );
		SettingsDialog::loadProxy(this);
	}

	std::string proxyHost() const
	{
		switch(s2.value("proxyConfig").toUInt())
		{
		case 0: return std::string();
		case 1: return systemProxy().hostName().toStdString();
		default: return s.value( "ProxyHost", QString::fromStdString(digidoc::XmlConfV4::proxyHost()) ).toString().toStdString();
		}
	}

	std::string proxyPort() const
	{
		switch(s2.value("proxyConfig").toUInt())
		{
		case 0: return std::string();
		case 1: return QString::number(systemProxy().port()).toStdString();
		default: return s.value( "ProxyPort", QString::fromStdString(digidoc::XmlConfV4::proxyPort()) ).toString().toStdString();
		}
	}

	std::string proxyUser() const
	{
		switch(s2.value("proxyConfig").toUInt())
		{
		case 0: return std::string();
		case 1: return systemProxy().user().toStdString();
		default: return s.value( "ProxyUser", QString::fromStdString(digidoc::XmlConfV4::proxyUser()) ).toString().toStdString();
		}
	}

	std::string proxyPass() const
	{
		switch(s2.value("proxyConfig").toUInt())
		{
		case 0: return std::string();
		case 1: return systemProxy().password().toStdString();
		default: return s.value( "ProxyPass", QString::fromStdString(digidoc::XmlConfV4::proxyPass()) ).toString().toStdString();
		}
	}

#ifdef Q_OS_MAC
	bool PKCS12Disable() const
	{ return s.value( "PKCS12Disable", digidoc::XmlConfV4::PKCS12Disable() ).toBool(); }
	std::string PKCS11Driver() const
	{ return QString( qApp->applicationDirPath() + "/" + QFileInfo( PKCS11_MODULE ).fileName() ).toStdString(); }
	std::string TSLCache() const
	{ return QDesktopServices::storageLocation(QDesktopServices::DataLocation).toStdString(); }
	bool TSLOnlineDigest() const
	{ return s2.value( "TSLOnlineDigest", digidoc::XmlConfV4::TSLOnlineDigest() ).toBool(); }

	void setProxyHost( const std::string &host )
	{ s.setValueEx( "ProxyHost", QString::fromStdString( host ), QString() ); }
	void setProxyPort( const std::string &port )
	{ s.setValueEx( "ProxyPort", QString::fromStdString( port ), QString() ); }
	void setProxyUser( const std::string &user )
	{ s.setValueEx( "ProxyUser", QString::fromStdString( user ), QString() ); }
	void setProxyPass( const std::string &pass )
	{ s.setValueEx( "ProxyPass", QString::fromStdString( pass ), QString() ); }
	void setPKCS12Cert( const std::string & ) {}
	void setPKCS12Pass( const std::string & ) {}
	void setPKCS12Disable( bool disable )
	{ s.setValueEx( "PKCS12Disable", disable, digidoc::XmlConfV4::PKCS12Disable() ); }
	void setTSLOnlineDigest( bool enable )
	{ s2.setValueEx( "TSLOnlineDigest", enable, digidoc::XmlConfV4::TSLOnlineDigest() ); }
#endif

	bool TSLAllowExpired() const
	{
		static enum {
			Undefined,
			Approved,
			Rejected
		} status = Undefined;
		if(status == Undefined)
		{
			QEventLoop e;
			QMetaObject::invokeMethod( qApp, "showTSLWarning", Q_ARG(QEventLoop*,&e) );
			status = e.exec() ? Approved : Rejected;
		}
		return status == Approved;
	}

private:
	Settings s;
	Settings s2;

	QNetworkProxy systemProxy() const
	{
		for(const QNetworkProxy &proxy: QNetworkProxyFactory::systemProxyForQuery())
		{
			if(proxy.type() == QNetworkProxy::HttpProxy)
				return proxy;
		}
		return QNetworkProxy();
	}
};

class ApplicationPrivate
{
public:
	QAction		*closeAction = nullptr, *newClientAction = nullptr, *newCryptoAction = nullptr;
	MacMenuBar	*bar = nullptr;
	QSigner		*signer = nullptr;
	QTranslator	appTranslator, commonTranslator, cryptoTranslator, qtTranslator;
	QString		lang;
	QTimer		lastWindowTimer;
	volatile bool ready = false;
};

Application::Application( int &argc, char **argv )
	: Common( argc, argv, APP, ":/images/digidoc_icon_128x128.png" )
	, d( new ApplicationPrivate )
{
	Q_INIT_RESOURCE(crypto_images);
	Q_INIT_RESOURCE(crypto_tr);
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

	detectPlugins();

	installTranslator( &d->appTranslator );
	installTranslator( &d->commonTranslator );
	installTranslator( &d->cryptoTranslator );
	installTranslator( &d->qtTranslator );
	loadTranslation( Settings::language() );

	// Actions
	d->closeAction = new QAction( this );
	d->closeAction->setShortcut( Qt::CTRL + Qt::Key_W );
	connect( d->closeAction, SIGNAL(triggered()), SLOT(closeWindow()) );

	d->newClientAction = new QAction( tr("New Client window"), this );
	d->newClientAction->setShortcut( Qt::CTRL + Qt::Key_N );
	connect( d->newClientAction, SIGNAL(triggered()), SLOT(showClient()) );
	d->newCryptoAction = new QAction( tr("New Crypto window"), this );
	d->newCryptoAction->setShortcut( Qt::CTRL + Qt::Key_C );
	connect( d->newCryptoAction, SIGNAL(triggered()), SLOT(showCrypto()) );

	setQuitOnLastWindowClosed( false );
	d->lastWindowTimer.setSingleShot(true);
	connect(&d->lastWindowTimer, &QTimer::timeout, [](){ if(topLevelWindows().isEmpty()) quit(); });
	connect(this, &Application::lastWindowClosed, [&](){ d->lastWindowTimer.start(10*1000); });

#if defined(Q_OS_MAC)
	d->bar = new MacMenuBar;
	d->bar->addAction( MacMenuBar::AboutAction, this, SLOT(showAbout()) );
	d->bar->addAction( MacMenuBar::PreferencesAction, this, SLOT(showSettings()) );
	d->bar->fileMenu()->addAction( d->newClientAction );
	d->bar->fileMenu()->addAction( d->newCryptoAction );
	d->bar->fileMenu()->addAction( d->closeAction );
	d->bar->dockMenu()->addAction( d->newClientAction );
	d->bar->dockMenu()->addAction( d->newCryptoAction );
#endif

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
#ifndef INTERNATIONAL
	if( provider != "EstEID Card CSP" )
		api = QSigner::CNG;
#endif
	if( args.contains("-capi") )
		api = QSigner::CAPI;
	if( args.contains("-cng") )
		api = QSigner::CNG;
#endif
	if( args.contains("-pkcs11") ) api = QSigner::PKCS11;

	try
	{
		digidoc::Conf::init( new DigidocConf );
		d->signer = new QSigner( api, this );

		QString cache = confValue(TSLCache).toString();
		QDir().mkpath( cache );
		for(const QString &file: QDir(":/TSL/").entryList())
		{
			if(!QFile::exists(cache + "/" + file))
			{
				QFile::copy(":/TSL/" + file, cache + "/" + file);
				QFile::setPermissions(cache + "/" + file, QFile::Permissions(0x6444));
			}
		}

		qRegisterMetaType<QEventLoop*>("QEventLoop*");
		digidoc::initializeEx( QString( "%1/%2 (%3)" )
			.arg( applicationName(), applicationVersion(), applicationOs() ).toUtf8().constData(),
			[](const digidoc::Exception *ex) {
				qDebug() << "TSL loading finished";
				if(ex) {
					QStringList causes;
					digidoc::Exception::ExceptionCode code = digidoc::Exception::General;
					int ddocError = -1;
					DigiDoc::parseException( *ex, causes, code, ddocError );
					QMetaObject::invokeMethod( qApp, "showWarning",
						Q_ARG(QString,tr("Failed to initalize.")), Q_ARG(QString,causes.join("\n")) );
				}
				qApp->d->ready = true;
				Q_EMIT qApp->TSLLoadingFinished();
			}
		);
	}
	catch( const digidoc::Exception &e )
	{
		showWarning( tr("Failed to initalize."), e );
		setQuitOnLastWindowClosed( true );
		return;
	}

	if( !args.isEmpty() || topLevelWindows().isEmpty() )
		parseArgs( args );
}

Application::~Application()
{
#ifndef Q_OS_MAC
	if( isRunning() )
	{
		delete d;
		return;
	}
	if( QtLocalPeer *obj = findChild<QtLocalPeer*>() )
		delete obj;
#endif
	delete d->bar;
	QEventLoop e;
	connect(this, &Application::TSLLoadingFinished, &e, &QEventLoop::quit);
	if( !d->ready )
		e.exec();
	digidoc::terminate();
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
	else if( Crypto::MainWindow *w = qobject_cast<Crypto::MainWindow*>(activeWindow()) )
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
	digidoc::ConfV4 *i = 0;
	try { i = digidoc::ConfV4::instance(); }
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
	case PKCS12Disable: return i->PKCS12Disable();
	case TSLUrl: r = i->TSLUrl().c_str(); break;
	case TSLCache: r = i->TSLCache().c_str(); break;
	case TSLCert: return QVariant::fromValue(SslCertificate::fromX509(i->TSLCert().handle()));
	case TSLOnlineDigest: return i->TSLOnlineDigest();
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

void Application::loadTranslation( const QString &lang )
{
	if( d->lang == lang )
		return;
	Settings().setValue( "Main/Language", d->lang = lang );

	if( lang == "en" ) QLocale::setDefault( QLocale( QLocale::English, QLocale::UnitedKingdom ) );
	else if( lang == "ru" ) QLocale::setDefault( QLocale( QLocale::Russian, QLocale::RussianFederation ) );
	else QLocale::setDefault( QLocale( QLocale::Estonian, QLocale::Estonia ) );

	d->appTranslator.load( ":/translations/" + lang );
	d->commonTranslator.load( ":/translations/common_" + lang );
	d->cryptoTranslator.load( ":/translations/crypto_" + lang );
	d->qtTranslator.load( ":/translations/qt_" + lang );
	if( d->closeAction ) d->closeAction->setText( tr("Close window") );
	if( d->newClientAction ) d->newClientAction->setText( tr("New Client window") );
	if( d->newCryptoAction ) d->newCryptoAction->setText( tr("New Crypto window") );
}

bool Application::notify( QObject *o, QEvent *e )
{
	try
	{
		return QApplication::notify( o, e );
	}
	catch( const digidoc::Exception &e )
	{
		showWarning( tr("Caught exception!"), e );
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
		params << (param != "-crypto" && !url.toLocalFile().isEmpty() ? url.toLocalFile() : param);
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
		showSettings( SettingsDialog::AccessCertSettings, params[0] );
	else if( crypto || (QStringList() << "cdoc").contains( suffix, Qt::CaseInsensitive ) )
		showCrypto( params );
	else
		showClient( params );
}

int Application::run()
{
#ifndef Q_OS_MAC
	if( isRunning() ) return 0;
#endif
	validate();
	return exec();
}

void Application::setConfValue( ConfParameter parameter, const QVariant &value )
{
	try
	{
		digidoc::XmlConfV4 *i = dynamic_cast<digidoc::XmlConfV4*>(digidoc::Conf::instance());
		if(!i)
			return;
		QByteArray v = value.toString().toUtf8();
		switch( parameter )
		{
		case ProxyHost: i->setProxyHost( v.isEmpty()? std::string() :  v.constData() ); break;
		case ProxyPort: i->setProxyPort( v.isEmpty()? std::string() : v.constData() ); break;
		case ProxyUser: i->setProxyUser( v.isEmpty()? std::string() : v.constData() ); break;
		case ProxyPass: i->setProxyPass( v.isEmpty()? std::string() : v.constData() ); break;
		case PKCS12Cert: i->setPKCS12Cert( v.isEmpty()? std::string() : v.constData() ); break;
		case PKCS12Pass: i->setPKCS12Pass( v.isEmpty()? std::string() : v.constData() ); break;
		case PKCS12Disable: i->setPKCS12Disable( value.toBool() ); break;
		case TSLOnlineDigest: i->setTSLOnlineDigest( value.toBool() ); break;
		case TSLCert:
		case TSLUrl:
		case TSLCache:
		case PKCS11Module: break;
		}
	}
	catch( const digidoc::Exception &e )
	{
		QStringList causes;
		digidoc::Exception::ExceptionCode code = digidoc::Exception::General;
		int ddocError = -1;
		DigiDoc::parseException( e, causes, code, ddocError );
		showWarning( tr("Caught exception!"), ddocError, causes.join("\n") );
	}
}

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

void Application::showSettings( int page, const QString &path )
{
	SettingsDialog *s = new SettingsDialog( page, activeWindow() );
	s->addAction( d->closeAction );
	s->open();
	if( !path.isEmpty() )
		s->activateAccessCert( path );
}

void Application::showTSLWarning(QEventLoop *e)
{
	e->exit( QMessageBox::Yes == QMessageBox::question(
		qApp->activeWindow(), Application::tr("DigiDoc3 Client"), Application::tr(
		"The renewal of Trust Service status List, used for digital signature validation, has failed. "
		"Please check your internet connection and make sure you have the latest ID-software version "
		"installed. Do you want to use the expired Trust Service List (TSL) for signature validation? "
		"<a href=\"http://www.id.ee/?id=37012\">Additional information</a>") ) );
}

void Application::showWarning( const QString &msg, const digidoc::Exception &e )
{
	QStringList causes;
	digidoc::Exception::ExceptionCode code = digidoc::Exception::General;
	int ddocError = -1;
	DigiDoc::parseException( e, causes, code, ddocError );
	showWarning( msg, causes.join("\n") );
}

void Application::showWarning( const QString &msg, const QString &details )
{
	showWarning( msg, -1, details );
}

void Application::showWarning( const QString &msg, int err, const QString &details, const QString &search )
{
	QMessageBox d( QMessageBox::Warning, tr("DigiDoc3 client"), msg, QMessageBox::Close, activeWindow() );
	d.setWindowModality( Qt::WindowModal );
	if( !details.isEmpty() )
	{
		//d.addButton( QMessageBox::Help );
		d.setDetailedText( details );
	}
	if( d.exec() == QMessageBox::Help )
		Common::showHelp( search.isEmpty() ? msg : search, err );
}

QSigner* Application::signer() const { return d->signer; }

QHash<QString,QString> Application::urls() const
{
	QHash<QString,QString> u = Common::urls();
	u["TSL"] = confValue(TSLUrl).toString();
	return u;
}

void Application::waitForTSL( const QString &file )
{
	if( !QStringList({"asice", "sce", "bdoc"}).contains(QFileInfo(file).suffix(), Qt::CaseInsensitive) )
		return;

	if( d->ready )
		return;

	QProgressDialog p( tr("Loading TSL lists"), QString(), 0, 0, qApp->activeWindow() );
	p.setWindowFlags( (p.windowFlags() | Qt::CustomizeWindowHint) & ~Qt::WindowCloseButtonHint );
	if( QProgressBar *bar = p.findChild<QProgressBar*>() )
		bar->setTextVisible( false );
	p.setMinimumWidth( 300 );
	p.setRange( 0, 100 );
	p.open();
	QTimer t;
	connect( &t, &QTimer::timeout, [&](){
		p.setValue( p.value() + 1 );
		if( p.value() == p.maximum() )
			p.reset();
		t.start( 100 );
	});
	t.start( 100 );
	QEventLoop e;
	connect(this, &Application::TSLLoadingFinished, &e, &QEventLoop::quit);
	if( !d->ready )
		e.exec();
	t.stop();
}
