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

#include "Application.h"

#ifdef Q_OS_WIN32
#include <QtCore/QDebug>
#include <QtCore/qt_windows.h>
#endif

int main( int argc, char *argv[] )
{
#if QT_VERSION > QT_VERSION_CHECK(5, 6, 0)
	QCoreApplication::setAttribute(Qt::AA_UseHighDpiPixmaps, true);
#ifdef Q_OS_WIN32
	char **newv = (char**)malloc((argc + 3) * sizeof(*newv));
	memmove(newv, argv, sizeof(*newv) * argc);
	newv[argc++] = (char*)"-platform";
	newv[argc++] = (char*)"windows:dpiawareness=1";
	newv[argc] = 0;
	argv = newv;

	HDC screen = GetDC(0);
	qreal dpi = GetDeviceCaps(screen, LOGPIXELSY);
	qreal scale = dpi / qreal(96);
	qputenv("QT_SCALE_FACTOR", QByteArray::number(scale));
	ReleaseDC(NULL, screen);
	qDebug() << "Current DPI:" << dpi << " setting scale:" << scale;
#else
	QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling, true);
#endif
#endif

	DdCliApplication cliApp( argc, argv );
	if( cliApp.isDiagnosticRun() )
	{
		return cliApp.run();
	}

	return Application( argc, argv ).run();
}
