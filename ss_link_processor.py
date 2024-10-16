# -*- coding: utf-8 -*-
"""
SSLinkProcessor - Обработка ShadowSocks ссылок

Copyright (c) 2023 Your Name

Licensed under the MIT License. See LICENSE file for more details.
"""

import base64
import argparse
import aiofiles
import aiohttp
import asyncio
import logging
import signal
import sys
import socket
from urllib.parse import unquote
from typing import Optional, Dict, Any
import json
from dataclasses import dataclass
import colorama
from colorama import Fore, Style

# Инициализация colorama
colorama.init()

# ----------------- Конфигурация и Настройки ----------------- #

@dataclass
class Config:
    """
    Класс конфигурации для настройки параметров работы приложения.
    """
    input_file: str
    output_file: str
    concurrency_limit: int = 10
    queue_size: int = 100
    log_level: str = "DEBUG"
    log_file: Optional[str] = None
    timeout: int = 10  # Таймаут для HTTP-запросов в секундах
    api_url: str = "https://ipapi.co/{ip}/json/"
    encoding: str = "utf-8"
    decode_only: bool = False  # Режим только декодирования
    ip_output_file: Optional[str] = None  # Файл для записи IP-адресов

    @staticmethod
    def from_args(args: argparse.Namespace) -> 'Config':
        """
        Создает объект Config из аргументов командной строки.

        :param args: Аргументы командной строки
        :return: Объект Config
        """
        return Config(
            input_file=args.input_file,
            output_file=args.output_file,
            concurrency_limit=args.concurrency,
            queue_size=args.queue_size,
            log_level=args.log_level.upper(),
            log_file=args.log_file,
            timeout=args.timeout,
            api_url=args.api_url,
            encoding=args.encoding,
            decode_only=args.decode_only,
            ip_output_file=args.ip_output_file
        )

# ----------------- Настройка Логирования ----------------- #

class ColorFormatter(logging.Formatter):
    """
    Класс форматтера для цветного логирования.
    """
    LEVEL_COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.MAGENTA
    }

    def format(self, record):
        log_color = self.LEVEL_COLORS.get(record.levelno, Fore.WHITE)
        message = super().format(record)
        return f"{log_color}{message}{Style.RESET_ALL}"

def setup_logging(config: Config):
    """
    Настраивает логирование на основе конфигурации.

    :param config: Объект Config с настройками логирования
    """
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, config.log_level, logging.INFO))

    formatter = ColorFormatter('%(asctime)s - %(levelname)s - %(message)s')

    # Обработчик для консоли
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Обработчик для файла, если указан
    if config.log_file:
        try:
            file_handler = logging.FileHandler(config.log_file)
            file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logging.error(f"Не удалось открыть файл логов {config.log_file}: {e}")

# ----------------- Флаги Завершения Работы ----------------- #

should_stop = False

def signal_handler(sig, frame):
    """
    Обрабатывает системные сигналы для корректного завершения работы.

    :param sig: сигнал завершения (SIGTERM, SIGINT и т.д.)
    :param frame: текущий стек вызовов (игнорируется)
    """
    global should_stop
    logging.info(f"Получен сигнал {sig}. Завершаем работу...")
    should_stop = True

# ----------------- Утилиты и Валидации ----------------- #

class SSUrlDecoder:
    """
    Класс для декодирования SS ссылок.
    """

    @staticmethod
    def validate_ss_url(ss_url: str) -> bool:
        """
        Проверяет валидность ссылки ShadowSocks.

        :param ss_url: Строка с SS ссылкой
        :return: True, если ссылка начинается с "ss://", иначе False
        """
        return ss_url.startswith("ss://")

    @staticmethod
    def decode_ss_url(ss_url: str) -> Dict[str, Any]:
        """
        Декодирует SS ссылку и возвращает конфигурацию сервера.

        :param ss_url: Строка SS ссылки
        :return: Словарь с конфигурацией (сервер, порт, пароль, метод шифрования, тег)
        :raises ValueError: Если формат SS ссылки некорректен
        """
        if not SSUrlDecoder.validate_ss_url(ss_url):
            raise ValueError("Неверный формат ссылки ShadowSocks (отсутствует префикс 'ss://')")

        ss_url = ss_url[5:]  # Убираем префикс "ss://"

        # Обрабатываем тег (если есть) после символа #
        tag = None
        if '#' in ss_url:
            ss_url, tag = ss_url.split('#', 1)
            tag = unquote(tag)

        # Проверяем наличие '@' для определения типа ссылки
        if '@' in ss_url:
            # Новый формат: ss://base64(user_info)@server:port
            user_info_encoded, server_info = ss_url.split('@', 1)

            # Декодируем user_info
            user_info = SSUrlDecoder.decode_base64(user_info_encoded)

            if ':' not in user_info:
                raise ValueError("Неверный формат user_info после декодирования")

            method, password = user_info.split(':', 1)

        else:
            # Старый формат: ss://base64(method:password@server:port)
            decoded_all = SSUrlDecoder.decode_base64(ss_url)

            if '@' not in decoded_all:
                raise ValueError("Неверный формат декодированной ссылки ShadowSocks")

            user_info, server_info = decoded_all.split('@', 1)

            if ':' not in user_info:
                raise ValueError("Неверный формат user_info после декодирования")

            method, password = user_info.split(':', 1)

        # Разбираем сервер и порт
        if ':' not in server_info:
            raise ValueError("Неверный формат server_info: отсутствует разделитель ':' между сервером и портом")

        server, port_str = server_info.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"Некорректный номер порта: {port_str}")

        return {
            "server": server,
            "server_port": port,
            "password": password,
            "method": method,
            "remarks": tag
        }

    @staticmethod
    def decode_base64(data: str) -> str:
        """
        Декодирует Base64 строку, добавляя padding, если необходимо.

        :param data: Base64-кодированная строка
        :return: Декодированная строка
        :raises ValueError: Если декодирование не удалось
        """
        # Заменяем URL-safe символы, если есть
        data = data.replace('-', '+').replace('_', '/')

        # Добавляем padding
        padding = '=' * (-len(data) % 4)
        data += padding

        try:
            decoded_bytes = base64.b64decode(data)
            return decoded_bytes.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Ошибка декодирования Base64: {e}")

class NetworkUtils:
    """
    Класс с сетевыми утилитами.
    """

    @staticmethod
    def is_valid_ip(address: str) -> bool:
        """
        Проверяет, является ли строка действительным IP-адресом.

        :param address: Строка с IP-адресом или доменом
        :return: True, если это валидный IP, иначе False
        """
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False

    @staticmethod
    def resolve_domain_to_ip(domain: str) -> Optional[str]:
        """
        Резолвит доменное имя в IP-адрес.

        :param domain: Доменное имя
        :return: Строка с IP-адресом или None, если резолвинг не удался
        """
        try:
            ip_address = socket.gethostbyname(domain)
            logging.debug(f"Домен {domain} успешно разрешён в IP {ip_address}")
            return ip_address
        except socket.gaierror as e:
            logging.error(f"Ошибка резолвинга домена {domain}: {e}")
            return None

# ----------------- Работа с API ----------------- #

class IPInfoFetcher:
    """
    Класс для получения информации о IP через API ipapi.co.
    """

    def __init__(self, config: Config):
        self.config = config

    async def get_ip_info(self, ip_address: str) -> Dict[str, Any]:
        """
        Получает информацию о IP через ipapi.co.

        :param ip_address: Строка с IP-адресом
        :return: JSON с информацией или ошибкой
        """
        url = self.config.api_url.format(ip=ip_address)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Referer': 'https://ipapi.co/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'TE': 'trailers'
        }
        try:
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        logging.debug(f"Получены данные для IP {ip_address}: {data}")
                        return data
                    else:
                        # Обработка ошибок на основе документации ipapi.co
                        try:
                            error_data = await response.json()
                            error_reason = error_data.get('reason', 'Unknown')
                            error_message = error_data.get('message', 'No message provided')
                            error_detail = f"{response.status} {response.reason} - {error_reason}: {error_message}"
                        except Exception:
                            error_detail = f"{response.status} {response.reason}"
                        logging.error(f"Ошибка при запросе для IP {ip_address}: {error_detail}")
                        return {"error": error_detail}
        except aiohttp.ClientError as e:
            error_msg = f"Ошибка соединения с ipapi.co для IP {ip_address}: {e}"
            logging.error(error_msg)
            return {"error": error_msg}
        except asyncio.TimeoutError:
            error_msg = f"Таймаут запроса для IP {ip_address}"
            logging.error(error_msg)
            return {"error": error_msg}
        except Exception as e:
            error_msg = f"Неизвестная ошибка при работе с ipapi.co для IP {ip_address}: {e}"
            logging.error(error_msg)
            return {"error": error_msg}

# ----------------- Обработчик SS ссылок ----------------- #

class SSLinkProcessor:
    """
    Класс для обработки SS ссылок.
    """

    def __init__(self, config: Config):
        self.config = config
        self.ip_fetcher = IPInfoFetcher(config)
        self.semaphore = asyncio.Semaphore(config.concurrency_limit)
        self.output_queue = asyncio.Queue(maxsize=config.queue_size)
        self.ip_addresses = []  # Список для хранения всех IP-адресов
        self.stats = {
            'total_links': 0,
            'processed_links': 0,
            'resolved_domains': 0,
            'ip_addresses': 0,
            'errors': 0
        }

    async def process_line(self, line: str, line_number: int):
        """
        Обрабатывает одну строку SS ссылки.

        :param line: Строка SS ссылки
        :param line_number: Номер строки в файле
        """
        if should_stop:
            logging.info("Обработка прервана пользователем.")
            return

        line = line.strip()
        if not line:
            return

        self.stats['total_links'] += 1

        try:
            config_decoded = SSUrlDecoder.decode_ss_url(line)
            self.stats['processed_links'] += 1

            server = config_decoded["server"]
            if NetworkUtils.is_valid_ip(server):
                server_ip = server
            else:
                server_ip = NetworkUtils.resolve_domain_to_ip(server)
                self.stats['resolved_domains'] += 1
                if server_ip is None:
                    raise ValueError(f"Не удалось резолвить домен {server}")

            # Добавляем IP-адрес в список
            self.ip_addresses.append(server_ip)
            self.stats['ip_addresses'] += 1

            if not self.config.decode_only:
                async with self.semaphore:
                    ip_info = await self.ip_fetcher.get_ip_info(server_ip)
                config_decoded["ip_info"] = ip_info
            else:
                config_decoded["ip_info"] = None  # В режиме только декодирования

            await self.output_queue.put(config_decoded)
            logging.info(f"Строка {line_number} обработана успешно.")
        except Exception as e:
            logging.error(f"Ошибка при обработке строки {line_number}: {e}")
            self.stats['errors'] += 1

    async def writer(self):
        """
        Асинхронный писатель в выходной файл.
        """
        try:
            async with aiofiles.open(self.config.output_file, mode='w', encoding=self.config.encoding) as out_f:
                while True:
                    config_decoded = await self.output_queue.get()
                    if config_decoded is None:
                        break
                    # Форматируем вывод как JSON строку для лучшей читаемости
                    await out_f.write(f"{json.dumps(config_decoded, ensure_ascii=False)}\n")
                    self.output_queue.task_done()
        except Exception as e:
            logging.error(f"Ошибка при записи в файл {self.config.output_file}: {e}")

    async def write_ip_addresses(self):
        """
        Пишет собранные IP-адреса в указанный файл.
        """
        if self.config.ip_output_file:
            try:
                async with aiofiles.open(self.config.ip_output_file, mode='w', encoding=self.config.encoding) as ip_file:
                    for ip in self.ip_addresses:
                        await ip_file.write(f"{ip}\n")
                logging.info(f"IP-адреса записаны в файл {self.config.ip_output_file}")
            except Exception as e:
                logging.error(f"Ошибка при записи IP-адресов в файл {self.config.ip_output_file}: {e}")

    def print_statistics(self):
        """
        Выводит подробную статистику работы.
        """
        print("\n" + "-" * 40)
        print(Fore.GREEN + "Статистика работы программы:" + Style.RESET_ALL)
        print(f"Всего ссылок: {self.stats['total_links']}")
        print(f"Успешно обработано ссылок: {self.stats['processed_links']}")
        print(f"Резолвлено доменов: {self.stats['resolved_domains']}")
        print(f"Получено IP-адресов: {self.stats['ip_addresses']}")
        print(f"Количество ошибок: {self.stats['errors']}")
        print("-" * 40)

    async def process_file(self):
        """
        Читает ссылки SS из файла и обрабатывает их.
        """
        logging.info(f"Загрузка ссылок из файла {self.config.input_file}")
        try:
            async with aiofiles.open(self.config.input_file, mode='r', encoding=self.config.encoding) as f:
                lines = await f.readlines()
        except FileNotFoundError:
            logging.error(f"Файл {self.config.input_file} не найден!")
            return
        except Exception as e:
            logging.error(f"Ошибка при чтении файла {self.config.input_file}: {e}")
            return

        total_lines = len(lines)
        logging.info(f"Найдено {total_lines} строк(и)")

        # Запуск писателя
        writer_task = asyncio.create_task(self.writer())

        # Создание задач для обработки строк
        tasks = []
        for i, line in enumerate(lines, start=1):
            if should_stop:
                logging.info("Обработка прервана пользователем.")
                break
            task = asyncio.create_task(self.process_line(line, i))
            tasks.append(task)

        # Ожидание завершения всех задач
        await asyncio.gather(*tasks, return_exceptions=True)

        # Завершение писателя
        await self.output_queue.put(None)
        await writer_task

        # Запись IP-адресов, если требуется
        if self.config.ip_output_file:
            await self.write_ip_addresses()

        # Вывод статистики
        self.print_statistics()

        logging.info("Обработка завершена.")

# ----------------- Точка входа ----------------- #

def main():
    """
    Основная функция для парсинга аргументов и запуска обработки SS ссылок.
    """
    parser = argparse.ArgumentParser(
        description="Обработка ShadowSocks ссылок: декодирование, резолвинг доменов и получение информации о IP."
    )
    parser.add_argument(
        'input_file',
        help="Путь к файлу с SS ссылками"
    )
    parser.add_argument(
        'output_file',
        help="Путь к файлу для записи результатов"
    )
    parser.add_argument(
        '--concurrency',
        type=int,
        default=10,
        help="Максимальное количество одновременных запросов (по умолчанию: 10)"
    )
    parser.add_argument(
        '--queue-size',
        type=int,
        default=100,
        help="Размер очереди для записи результатов (по умолчанию: 100)"
    )
    parser.add_argument(
        '--log-level',
        type=str,
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help="Уровень логирования (по умолчанию: INFO)"
    )
    parser.add_argument(
        '--log-file',
        type=str,
        default=None,
        help="Путь к файлу для записи логов (по умолчанию: вывод в консоль)"
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help="Таймаут для HTTP-запросов в секундах (по умолчанию: 10)"
    )
    parser.add_argument(
        '--api-url',
        type=str,
        default="https://ipapi.co/{ip}/json/",
        help="URL API для получения информации об IP (по умолчанию: https://ipapi.co/{ip}/json/)"
    )
    parser.add_argument(
        '--encoding',
        type=str,
        default="utf-8",
        help="Кодировка файлов (по умолчанию: utf-8)"
    )
    parser.add_argument(
        '--decode-only',
        action='store_true',
        help="Включить режим только декодирования без запросов к ipapi.co"
    )
    parser.add_argument(
        '--ip',
        dest='ip_output_file',
        type=str,
        default=None,
        help="Путь к файлу для записи IP-адресов (необязательный)"
    )

    args = parser.parse_args()

    # Создаем конфигурационный объект
    config = Config.from_args(args)

    # Настраиваем логирование
    setup_logging(config)
    logging.debug(f"Конфигурация: {config}")

    # Подключаем обработку системных сигналов
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Запускаем асинхронную обработку
    try:
        processor = SSLinkProcessor(config)
        asyncio.run(processor.process_file())
    except KeyboardInterrupt:
        logging.info("Программа прервана пользователем.")
    except Exception as e:
        logging.error(f"Неизвестная ошибка: {e}")

if __name__ == "__main__":
    main()
