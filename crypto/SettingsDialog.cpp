/*
 * QDigiDocCrypto
 *
 * Copyright (C) 2009-2013 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009-2013 Raul Metsma <raul@innovaatik.ee>
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

#include "SettingsDialog.h"

#include "ui_SettingsDialog.h"

#include <common/FileDialog.h>
#include <common/Settings.h>

using namespace Crypto;

SettingsDialog::SettingsDialog( QWidget *parent )
:	QDialog( parent )
,	d( new Ui::SettingsDialog )
{
	d->setupUi( this );
	setAttribute( Qt::WA_DeleteOnClose );

	Settings s;
	s.beginGroup( "Crypto" );

	d->showIntro->setChecked( s.value( "Intro", true ).toBool() );
#ifdef Q_OS_MAC
	d->label->hide();
	d->defaultSameDir->hide();
	d->defaultDir->hide();
	d->selectDefaultDir->hide();
	d->askSaveAs->hide();
#else
	d->defaultSameDir->setChecked( s.value( "DefaultDir" ).isNull() );
	d->defaultDir->setText( s.value( "DefaultDir" ).toString() );
	d->askSaveAs->setChecked( s.value( "AskSaveAs", true ).toBool() );
#endif
	s.endGroup();
}

SettingsDialog::~SettingsDialog() { delete d; }

void SettingsDialog::on_selectDefaultDir_clicked()
{
#ifndef Q_OS_MAC
	QString dir = Settings().value( "Crypto/DefaultDir" ).toString();
	dir = FileDialog::getExistingDirectory( this, tr("Select folder"), dir );
	if( !dir.isEmpty() )
	{
		Settings().setValue( "Crypto/DefaultDir", dir );
		d->defaultDir->setText( dir );
	}
	d->defaultSameDir->setChecked( d->defaultDir->text().isEmpty() );
#endif
}

void SettingsDialog::save()
{
	Settings s;
	s.beginGroup( "Crypto" );
	s.setValue( "Intro", d->showIntro->isChecked() );
#ifndef Q_OS_MAC
	s.setValue( "AskSaveAs", d->askSaveAs->isChecked() );
	if( d->defaultSameDir->isChecked() )
	{
		d->defaultDir->clear();
		s.remove( "DefaultDir" );
	}
#endif
}
