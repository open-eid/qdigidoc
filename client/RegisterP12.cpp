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

#include "RegisterP12.h"

#include <common/Settings.h>
#include "DigiDoc.h"

#include <QDesktopServices>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QMessageBox>
#include <QTranslator>

RegisterP12::RegisterP12( const QString &cert, QWidget *parent )
:	QWidget( parent )
{
	QString lang = Settings().value( "Main/Language", "et" ).toString();
	QTranslator *appTranslator = new QTranslator( this );
	QTranslator *qtTranslator = new QTranslator( this );
	QApplication::instance()->installTranslator( appTranslator );
	QApplication::instance()->installTranslator( qtTranslator );
	appTranslator->load( ":/translations/" + lang );
	qtTranslator->load( ":/translations/qt_" + lang );

	setupUi( this );
	try { digidoc::initialize(); } catch( const digidoc::Exception & ) {}
	p12Cert->setText( cert );
}

RegisterP12::~RegisterP12() { digidoc::terminate(); }

void RegisterP12::on_buttonBox_accepted()
{
	QFileInfo file( p12Cert->text() );
	if( !file.isFile() )
	{
		QMessageBox::warning( this, windowTitle(),
			tr("No OCSP PKCS#12 certificate selected") );
		return;
	}

	QDir().mkpath( QDesktopServices::storageLocation( QDesktopServices::DataLocation ) );
	QString dest = QString( "%1/%2" )
		.arg( QDesktopServices::storageLocation( QDesktopServices::DataLocation ) )
		.arg( file.fileName() );

	if( QFile::exists( dest ) )
		QFile::remove( dest );
	if( !QFile::copy( p12Cert->text(), dest ) )
	{
		QMessageBox::warning( this, windowTitle(), tr("Failed to copy file") );
		return;
	}

	DigiDoc::setConfValue( DigiDoc::PKCS12Cert, dest );
	DigiDoc::setConfValue( DigiDoc::PKCS12Pass, p12Pass->text() );
	close();
}

void RegisterP12::on_p12Button_clicked()
{
	QString cert = QFileDialog::getOpenFileName( this, tr("Select PKCS#12 certificate"),
		QFileInfo( p12Cert->text() ).path(), tr("PKCS#12 Certificates (*.p12 *.p12d)") );
	if( !cert.isEmpty() )
		p12Cert->setText( cert );
}
