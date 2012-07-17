/*
 * QDigiDocClient
 *
 * Copyright (C) 2009-2012 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009-2012 Raul Metsma <raul@innovaatik.ee>
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
#include "ui_RegisterP12.h"

#include "Application.h"

#include <common/CertificateWidget.h>
#include <common/FileDialog.h>
#include <common/Settings.h>
#include <common/SslCertificate.h>

#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QUrl>
#include <QtGui/QDesktopServices>
#include <QtGui/QDropEvent>
#include <QtGui/QMessageBox>

RegisterP12::RegisterP12( const QString &cert )
:	QWidget()
,	d( new Ui::RegisterP12 )
{
	setAttribute( Qt::WA_DeleteOnClose, true );
	d->setupUi( this );
	d->p12Cert->installEventFilter( this );
	d->p12Cert->setText( cert );
}

RegisterP12::~RegisterP12() { delete d; }

bool RegisterP12::eventFilter( QObject *o, QEvent *e )
{
	if( o == d->p12Cert && e->type() == QEvent::Drop )
	{
		QDropEvent *drop = static_cast<QDropEvent*>(e);
		if( drop->mimeData()->hasUrls() )
		{
			d->p12Cert->setText( drop->mimeData()->urls().value( 0 ).toLocalFile() );
			return true;
		}
	}
	return QWidget::eventFilter( o, e );
}

void RegisterP12::on_buttonBox_accepted()
{
	QFileInfo file( d->p12Cert->text() );
	if( !file.isFile() )
	{
		QMessageBox::warning( this, windowTitle(),
			tr("No server access certificate selected") );
		return;
	}

	QString path = QDesktopServices::storageLocation( QDesktopServices::DataLocation );
	QDir().mkpath( path );
	QString dest = QString( "%1/%2" ).arg( path, file.fileName() );

	if( QFile::exists( dest ) )
		QFile::remove( dest );
	if( !QFile::copy( d->p12Cert->text(), dest ) )
	{
		QMessageBox::warning( this, windowTitle(), tr("Failed to copy file") );
		return;
	}

	Application::setConfValue( Application::PKCS12Cert, dest );
	Application::setConfValue( Application::PKCS12Pass, d->p12Pass->text() );
	close();
}

void RegisterP12::on_showP12Cert_clicked()
{
	QFile f( d->p12Cert->text() );
	if( !f.open( QIODevice::ReadOnly ) )
		return;

	PKCS12Certificate cert( &f, d->p12Pass->text().toLatin1() );
	f.close();
	if( cert.certificate().isNull() )
		return;
	CertificateDialog d( cert.certificate() );
	d.exec();
}

void RegisterP12::on_p12Button_clicked()
{
	QString cert = FileDialog::getOpenFileName( this, tr("Select server access certificate"),
		QFileInfo( d->p12Cert->text() ).path(), tr("Server access certificates (*.p12 *.p12d)") );
	if( !cert.isEmpty() )
		d->p12Cert->setText( cert );
}

void RegisterP12::on_p12Cert_textChanged( const QString & )
{ validateP12Cert(); }

void RegisterP12::on_p12Pass_textChanged( const QString & )
{ validateP12Cert(); }

void RegisterP12::validateP12Cert()
{
	d->showP12Cert->setEnabled( false );
	d->p12Error->clear();
	QFile f( d->p12Cert->text() );
	if( !f.open( QIODevice::ReadOnly ) )
		return;

	PKCS12Certificate cert( &f, d->p12Pass->text().toLatin1() );
	switch( cert.error() )
	{
	case PKCS12Certificate::NullError:
		d->showP12Cert->setEnabled( !cert.isNull() );
		break;
	case PKCS12Certificate::InvalidPasswordError:
		d->p12Error->setText( tr("Invalid password") );
		break;
	default:
		d->p12Error->setText( tr("Server access certificate error: %1").arg( cert.errorString() ) );
		break;
	}
}
