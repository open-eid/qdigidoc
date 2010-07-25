/*
 * QDigiDocClient
 *
 * Copyright (C) 2009 Jargo Kőster <jargo@innovaatik.ee>
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

#include "Application.h"

#include "DigiDoc.h"
#include "MainWindow.h"
#include "RegisterP12.h"
#include "version.h"

#include "common/Common.h"

#include <digidocpp/ADoc.h>
#include <digidocpp/crypto/cert/DirectoryX509CertStore.h>

#include <QDesktopServices>
#ifdef Q_OS_LINUX
#include <QFile>
#endif
#include <QFileInfo>
#include <QMessageBox>
#include <QPalette>
#include <QSslCertificate>

#include <openssl/ssl.h>

Application::Application( int &argc, char **argv )
:	QApplication( argc, argv )
{
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

	qRegisterMetaType<QSslCertificate>("QSslCertificate");

	Common *common = new Common( this );
	QDesktopServices::setUrlHandler( "browse", common, "browse" );
	QDesktopServices::setUrlHandler( "mailto", common, "mailTo" );

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
		showWarning( tr("Failed to initalize QDigiDocClient.<br />%1").arg( causes.join("\n") ) );
		return;
	}

	QWidget *widget;
	QStringList args = arguments();
	args.removeFirst();
	QStringList exts = QStringList() << "p12" << "p12d";
	if( !args.isEmpty() && exts.contains( QFileInfo( args.value(0) ).suffix(), Qt::CaseInsensitive ) )
	{
		widget = new RegisterP12( args.value(0) );
	}
	else
	{
		SSL_load_error_strings();
		SSL_library_init();

		widget = new MainWindow();
	}

	widget->show();
}

Application::~Application()
{
	digidoc::X509CertStore::destroy();
	digidoc::terminate();
}

void Application::showWarning( const QString &msg )
{
	QMessageBox d( QMessageBox::Warning, tr("DigiDoc3 client"), msg, QMessageBox::Close | QMessageBox::Help, activeWindow() );
	if( d.exec() == QMessageBox::Help )
		Common::showHelp( msg );
}
