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

#include "MainWindow.h"
#include "RegisterP12.h"
#include "version.h"

#include <QApplication>
#include <QFileInfo>

#include <openssl/ssl.h>

#ifdef Q_OS_LINUX
#include <QFile>
QByteArray cryptoFileEncoder( const QString &filename ) { return filename.toUtf8(); }
QString cryptoFileDecoder( const QByteArray &filename ) { return QString::fromUtf8( filename ); }
#endif

int main( int argc, char *argv[] )
{
	qputenv( "LANG", "en_US.UTF-8" );
#ifdef Q_OS_LINUX
	QFile::setEncodingFunction( cryptoFileEncoder );
	QFile::setDecodingFunction( cryptoFileDecoder );
#endif
	QApplication a( argc, argv );
	a.setApplicationName( APP );
	a.setApplicationVersion( VER_STR( FILE_VER_DOT ) );
	a.setOrganizationDomain( DOMAINURL );
	a.setOrganizationName( ORG );
	a.setStyleSheet(
		"QDialogButtonBox { dialogbuttonbox-buttons-have-icons: 0; }\n"
		"* { font: 12px \"Arial, Liberation Sans\"; }"
	);
	QPalette p = a.palette();
	p.setBrush( QPalette::Link, QBrush( "#509B00" ) );
	p.setBrush( QPalette::LinkVisited, QBrush( "#509B00" ) );
	a.setPalette( p );

	QStringList args = a.arguments();
	QWidget *w;
	QStringList exts = QStringList() << "p12" << "p12d";
	if( args.size() > 1 && exts.contains( QFileInfo( args.value(1) ).suffix(), Qt::CaseInsensitive ) )
	{
		w = new RegisterP12( args.value(1) );
	}
	else
	{
		SSL_load_error_strings();
		SSL_library_init();

		w = new MainWindow();
	}

	w->show();
	int ret = a.exec();
	delete w;
	return ret;
}
