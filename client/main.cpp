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

#include "Application.h"

#include <QProcess>
#include <QSysInfo>

int main( int argc, char *argv[] )
{
	if( QSysInfo::MacintoshVersion == QSysInfo::MV_10_5 && QSysInfo::WordSize == 64 )
	{
		QCoreApplication app( argc, argv );
		return QProcess::startDetached( "arch", QStringList() << "-i386" << app.applicationFilePath() << app.arguments() );
	}

	Application a( argc, argv );
	return a.isRunning() ? 0 : a.exec();
}
