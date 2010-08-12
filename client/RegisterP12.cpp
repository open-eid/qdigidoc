/*
 * QDigiDocClient
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

#include "RegisterP12.h"

#include "common/Settings.h"
#include "Application.h"

#include <QDesktopServices>
#include <QDropEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QMessageBox>
#include <QUrl>

RegisterP12::RegisterP12( const QString &cert )
:	QWidget()
{
	qApp->loadTranslation( Settings().value( "Main/Language", "et" ).toString() );
	setAttribute( Qt::WA_DeleteOnClose, true );
	setupUi( this );
	p12Cert->installEventFilter( this );
	p12Cert->setText( cert );
}


bool RegisterP12::eventFilter( QObject *o, QEvent *e )
{
	if( o == p12Cert && e->type() == QEvent::Drop )
	{
		QDropEvent *d = static_cast<QDropEvent*>(e);
		if( d->mimeData()->hasUrls() )
		{
			p12Cert->setText( d->mimeData()->urls().value( 0 ).toLocalFile() );
			return true;
		}
	}
	return QWidget::eventFilter( o, e );
}

void RegisterP12::on_buttonBox_accepted()
{
	QFileInfo file( p12Cert->text() );
	if( !file.isFile() )
	{
		QMessageBox::warning( this, windowTitle(),
			tr("No OCSP PKCS#12 certificate selected") );
		return;
	}

	QString path = QDesktopServices::storageLocation( QDesktopServices::DataLocation );
	QDir().mkpath( path );
	QString dest = QString( "%1/%2" ).arg( path, file.fileName() );

	if( QFile::exists( dest ) )
		QFile::remove( dest );
	if( !QFile::copy( p12Cert->text(), dest ) )
	{
		QMessageBox::warning( this, windowTitle(), tr("Failed to copy file") );
		return;
	}

	Application::setConfValue( Application::PKCS12Cert, dest );
	Application::setConfValue( Application::PKCS12Pass, p12Pass->text() );
	close();
}

void RegisterP12::on_p12Button_clicked()
{
	QString cert = QFileDialog::getOpenFileName( this, tr("Select PKCS#12 certificate"),
		QFileInfo( p12Cert->text() ).path(), tr("PKCS#12 Certificates (*.p12 *.p12d)") );
	if( !cert.isEmpty() )
		p12Cert->setText( cert );
}
